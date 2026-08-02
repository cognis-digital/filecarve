# polyglot/ruby/signature_scanning.rb

require 'fileutils'

module Filecarve
  module SignatureScanning
    class Scanner
      attr_reader :image_path, :signatures, :output_dir

      def initialize(image_path, signatures, output_dir = nil)
        @image_path = image_path
        @signatures = signatures
        @output_dir = output_dir || File.join(Dir.pwd, 'carved_files')
        FileUtils.mkdir_p(@output_dir) unless File.directory?(@output_dir)
      end

      def run
        file = File.open(@image_path, 'rb')
        offset = 0
        signature_count = 0

        while (chunk = file.read(1024 * 1024)) # Read 1MB chunks
          signatures.each do |sig|
            match = chunk.match(sig[:pattern])
            next unless match

            if sig[:type] == :file
              filename = File.join(@output_dir, "carved_#{signature_count}.#{sig[:extension]}")
              write_file(file, filename, sig[:length])
              signature_count += 1
            elsif sig[:type] == :memory
              puts "Found memory dump signature at offset #{offset} (#{sig[:description]})"
            end
          end
        end

        puts "Total files carved: #{signature_count}"
      end

      private

      def write_file(file, filename, length)
        content = ''
        remaining = length
        while remaining > 0
          chunk = file.read(remaining)
          content += chunk
          remaining -= chunk.size
        end
        File.open(filename, 'wb') do |f|
          f.write(content)
        end
      end
    end

    # Example usage
    def self.run_example
      signatures = [
        { type: :file, pattern: /PNG\r\n/, description: 'PNG Image', extension: 'png', length: 8 },
        { type: :file, pattern: /GIF8/, description: 'GIF Image', extension: 'gif', length: 6 },
        { type: :file, pattern: /JPEG/, description: 'JPEG Image', extension: 'jpg', length: 4 },
        { type: :memory, pattern: /MZ/, description: 'Windows Executable' }
      ]

      scanner = Scanner.new('example_disk_image.raw', signatures)
      scanner.run
    end
  end
end

# Run example when file is executed
if __FILE__ == $0
  Filecarve::SignatureScanning.run_example
end