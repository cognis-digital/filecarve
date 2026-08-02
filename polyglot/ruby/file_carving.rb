# polyglot/ruby/file_carving.rb

require 'fileutils'

module FileCarving
  class Carver
    attr_reader :image_path, :output_dir, :signatures

    def initialize(image_path, output_dir, signatures)
      @image_path = image_path
      @output_dir = output_dir
      @signatures = signatures
    end

    def carve!
      FileUtils.mkdir_p(@output_dir) unless File.directory?(@output_dir)

      File.open(@image_path, 'rb') do |image|
        buffer = ''
        current_file = nil

        image.each_byte do |byte|
          buffer += [byte].pack('C')

          # Check if buffer matches any signature
          @signatures.each do |signature|
            if buffer.end_with?(signature)
              # Start of file found, prepare to carve
              current_file = {
                name: generate_filename(signature),
                content: buffer,
                offset: image.pos - signature.size
              }
              break
            end
          end

          # If a file was started, check for end of file
          if current_file
            @signatures.each do |signature|
              if buffer.end_with?(signature)
                # End of file found, write to disk
                write_file(current_file)
                current_file = nil
                break
              end
            end
          end
        end

        # Handle any remaining buffer that might be part of a file
        if current_file
          write_file(current_file)
        end
      end
    end

    private

    def generate_filename(signature)
      signature.gsub(/\W/, '_').downcase + '.bin'
    end

    def write_file(file_info)
      file_path = File.join(@output_dir, file_info[:name])
      File.open(file_path, 'wb') do |f|
        f.write(file_info[:content])
      end
      puts "Recovered file: #{file_path} (offset: #{file_info[:offset]})"
    end
  end

  def self.run(image_path, output_dir, signatures)
    Carver.new(image_path, output_dir, signatures).carve!
  end
end

# Demo entry point
if __FILE__ == $0
  # Example signatures (e.g., common file headers)
  signatures = [
    "\x50\x4b\x03\x04", # ZIP
    "\x49\x49\x2A\x00", # JPEG
    "\x42\x4D",         # BMP
    "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", # PNG
    "\x25\x50\x44\x46", # PDF
    "\x47\x49\x46\x38", # GIF
    "\x00\x00\x01\xB2", # MP3
    "\xFF\xD8\xFF",     # JPEG (alternative)
    "\x52\x49\x46\x46", # WAV
    "\x49\x49\x49\x49", # TIFF
  ]

  output_dir = 'carved_files'
  image_path = 'disk_image.raw' # Replace with your disk image path

  puts "Starting file carving..."
  FileCarving.run(image_path, output_dir, signatures)
  puts "File carving completed. Files saved to #{output_dir}."
end