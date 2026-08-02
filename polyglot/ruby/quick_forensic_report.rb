# polyglot/ruby/quick_forensic_report.rb

require 'fileutils'
require 'digest'

class QuickForensicReport
  attr_reader :report_path, :signature_map, :results

  def initialize(report_path = 'forensic_report.txt')
    @report_path = report_path
    @signature_map = {
      'txt' => ['\x0D\x0A', '\x0A'],
      'jpg' => ['\xFF\xD8\xFF'],
      'png' => ['\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'],
      'pdf' => ['\x25\x50\x44\x46'],
      'zip' => ['\x50\x4B\x03\x04'],
      'exe' => ['\x4D\x5A'],
      'elf' => ['\x7F\x45\x4C\x46']
    }
    @results = []
  end

  def generate_from_image(image_path)
    File.open(image_path, 'rb') do |file|
      buffer = ''
      while (chunk = file.read(1024))
        buffer += chunk
        process_buffer(buffer)
      end
    end
    write_report
  end

  private

  def process_buffer(buffer)
    @signature_map.each do |ext, signatures|
      signatures.each do |sig|
        if buffer.include?(sig)
          offset = buffer.index(sig)
          filename = "carved_file_#{Digest::SHA1.hexdigest(sig)}#{ext}"
          save_carved_file(buffer, offset, sig.size, filename)
          @results << { signature: sig.unpack('H*')[0], file: filename, offset: offset }
        end
      end
    end
  end

  def save_carved_file(data, offset, size, filename)
    FileUtils.mkdir_p(File.dirname(filename))
    File.open(filename, 'wb') do |f|
      f.write(data[offset...offset + size])
    end
  end

  def write_report
    File.open(@report_path, 'w') do |file|
      file.puts "Quick Forensic Report"
      file.puts "---------------------"
      file.puts "\nFound files:"
      @results.each do |result|
        file.puts "Signature: #{result[:signature]} (#{result[:signature].bytesize} bytes)"
        file.puts "File: #{result[:file]}"
        file.puts "Offset: #{result[:offset]}"
        file.puts "---------------------"
      end
      file.puts "\nReport saved to #{@report_path}"
    end
  end
end

# Entry point/demo
if __FILE__ == $0
  report = QuickForensicReport.new('forensic_report.txt')
  report.generate_from_image('disk_image.raw')
end