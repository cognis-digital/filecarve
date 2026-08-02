# polyglot/ruby/memory_dump_analysis.rb

require 'fileutils'
require 'digest'

class MemoryDumpAnalyzer
  attr_reader :dump_path, :results

  def initialize(dump_path)
    @dump_path = dump_path
    @results = []
  end

  def analyze
    # Common file signatures (hex) for common file types
    signatures = {
      'PE32' => ['4D5A', '5A4D'],
      'ELF' => ['7F45', '457F'],
      'ZIP' => ['504B', '4B50'],
      'JPEG' => ['FFD8', 'D8FF'],
      'PNG' => ['8950', '5089'],
      'PDF' => ['2550', '5025'],
      'TXT' => ['4142', '4241'], # Simple ASCII signature for text
      'HTML' => ['3C21', '213C'], # '<!' or '!'
    }

    # Read the entire dump into memory
    content = File.binread(@dump_path)

    signatures.each do |file_type, hex_signatures|
      hex_signature = hex_signatures.first
      offset = content.index(hex_signature)
      next unless offset

      # Extract a chunk around the signature for better accuracy
      start = offset - 100
      end_pos = offset + 200
      chunk = content[start..end_pos]

      # Check if the chunk contains any of the alternate signatures
      found_alternate = hex_signatures.any? do |alt|
        chunk.include?(alt)
      end

      unless found_alternate
        # Check for ASCII approximation if no hex signature matches
        ascii_signature = file_type.downcase.gsub(/\w+/) { |word| word[0] }
        if content.include?(ascii_signature)
          found_alternate = true
        end
      end

      next unless found_alternate

      # Extract the file content from the chunk
      file_content = chunk.split(hex_signature).first
      file_name = "#{file_type}_#{Digest::SHA1.hexdigest(file_content)}"

      # Save the extracted file
      FileUtils.mkdir_p('extracted')
      File.open("extracted/#{file_name}", 'wb') do |f|
        f.write(file_content)
      end

      @results << {
        type: file_type,
        offset: offset,
        size: file_content.size,
        path: "extracted/#{file_name}"
      }
    end
  end

  def print_results
    puts "\nMemory Dump Analysis Results:"
    @results.each do |result|
      puts "Found #{result[:type]} at offset #{result[:offset]} (size: #{result[:size]} bytes)"
      puts "Saved to: #{result[:path]}"
    end
  end
end

# Entry point for demo
if __FILE__ == $0
  dump_path = 'sample_memory_dump.bin' # Replace with actual memory dump path
  analyzer = MemoryDumpAnalyzer.new(dump_path)
  analyzer.analyze
  analyzer.print_results
end