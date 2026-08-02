# polyglot/ruby/disk_image_processing.rb

require 'fileutils'

module Filecarve
  module DiskImageProcessing
    def self.process_disk_image(image_path, output_dir, signatures)
      FileUtils.mkdir_p(output_dir) unless Dir.exist?(output_dir)

      File.open(image_path, 'rb') do |image|
        buffer = ''
        image.each_byte do |byte|
          buffer += [byte].pack('C')
          signatures.each do |sig|
            if buffer.end_with?(sig)
              offset = image.pos - sig.size
              filename = "carved_#{sig.unpack('H*').first}_#{offset}.bin"
              output_path = File.join(output_dir, filename)
              FileUtils.cp(File.open(image_path, 'rb'), output_path)
              puts "Recovered file: #{filename} (signature: #{sig.unpack('H*').first}, offset: #{offset})"
            end
          end
        end
      end
    end

    def self.run_demo
      # Example signatures for common file types (hex format)
      signatures = [
        '49444154', # .dat (example signature)
        '52494646', # .wav
        '47494638', # .gif
        '504B0304', # .zip
        '424D',     # .bmp
        '49492A',   # .tiff
        '4D546864', # .mov
        '494E5441', # .ntfs (partial)
        '534D4249', # .mdb (Microsoft Access)
        '4D534644'  # .msf (Microsoft Office)
      ]

      image_path = 'sample_disk_image.dd'
      output_dir = 'carved_files'

      puts "Processing disk image '#{image_path}'..."
      process_disk_image(image_path, output_dir, signatures)
      puts "Done. Files saved to '#{output_dir}'."
    end
  end
end

# Run demo if file is executed directly
if __FILE__ == $0
  Filecarve::DiskImageProcessing.run_demo
end