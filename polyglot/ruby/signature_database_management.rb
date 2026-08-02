# polyglot/ruby/signature_database_management.rb

require 'set'

module Filecarve
  module SignatureDatabase
    class Database
      attr_reader :signatures, :file_types

      def initialize
        @signatures = {}
        @file_types = Set.new
      end

      def add_signature(signature_name, pattern, file_type)
        raise ArgumentError, "Signature name cannot be empty" if signature_name.empty?
        raise ArgumentError, "Pattern cannot be empty" if pattern.empty?

        unless pattern.is_a?(String) && pattern.start_with?(/\A(?:(?:\d+|\w+|\W)+)\z/)
          raise ArgumentError, "Invalid pattern format"
        end

        @signatures[signature_name] = {
          pattern: pattern,
          file_type: file_type
        }
        @file_types.add(file_type)
      end

      def remove_signature(signature_name)
        if @signatures.key?(signature_name)
          @file_types.delete(@signatures[signature_name][:file_type])
          @signatures.delete(signature_name)
        else
          raise KeyError, "Signature '#{signature_name}' not found"
        end
      end

      def list_signatures
        @signatures.keys
      end

      def list_file_types
        @file_types.to_a
      end

      def find_matching_signatures(data)
        matches = {}
        @signatures.each do |name, sig|
          if data.include?(sig[:pattern])
            matches[name] = sig[:file_type]
          end
        end
        matches
      end
    end

    # Example usage
    def self.run_demo
      db = Database.new

      puts "Adding signatures..."
      db.add_signature("txt", "text", "Text File")
      db.add_signature("jpg", "jpeg", "JPEG Image")
      db.add_signature("png", "png", "PNG Image")

      puts "\nList of signatures:"
      puts db.list_signatures.join(', ')

      puts "\nList of file types:"
      puts db.list_file_types.join(', ')

      puts "\nTesting signature matching..."
      test_data = "This is a sample text file with some text content."
      matches = db.find_matching_signatures(test_data)
      puts "Matches found: #{matches.empty? ? 'none' : matches.size}"

      puts "\nRemoving 'txt' signature..."
      db.remove_signature("txt")

      puts "\nList of signatures after removal:"
      puts db.list_signatures.join(', ')
    end
  end
end

# Run the demo if this file is executed directly
if __FILE__ == $0
  Filecarve::SignatureDatabase.run_demo
end