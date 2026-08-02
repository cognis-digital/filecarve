#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_SIGNATURES 100
#define MAX_SIGNATURE_LENGTH 256
#define BUFFER_SIZE 4096

typedef struct {
    char signature[MAX_SIGNATURE_LENGTH];
    char *file_type;
} Signature;

// Sample known file signatures (can be extended)
Signature known_signatures[] = {
    {"\x50\x4b\x03\x04", "ZIP"},
    {"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "MS Office (OLE)"},
    {"\x49\x49\x2A\x00", "TIFF"},
    {"\x42\x4D", "Windows Bitmap"},
    {"\x52\x61\x72\x21\x19\x00\x01\x00", "RAR"},
    {"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "PNG"},
    {"\xFF\xD8\xFF", "JPEG"},
    {"\x47\x49\x46\x38", "GIF"},
    {"\x25\x50\x44\x46", "PDF"},
    {"\x50\x4B\x01\x02", "ZIP (stream)"},
};

int count_signatures() {
    return sizeof(known_signatures) / sizeof(known_signatures[0]);
}

void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s <image_file>\n", progname);
    fprintf(stderr, "Carves files from disk image or memory dump by known file signatures.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    FILE *image_file = fopen(argv[1], "rb");
    if (!image_file) {
        perror("Failed to open image file");
        return 1;
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    long file_pos = 0;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), image_file)) > 0) {
        for (int i = 0; i < count_signatures(); i++) {
            int match = 1;
            for (int j = 0; j < strlen(known_signatures[i].signature); j++) {
                if (file_pos + j >= ftell(image_file)) {
                    match = 0;
                    break;
                }
                if (buffer[j] != known_signatures[i].signature[j]) {
                    match = 0;
                    break;
                }
            }

            if (match) {
                printf("Found %s file at position %ld\n", known_signatures[i].file_type, file_pos);
                // For demo, carve the file by reading until EOF or next signature
                FILE *carved_file = fopen(known_signatures[i].file_type, "wb");
                if (!carved_file) {
                    perror("Failed to create carved file");
                    continue;
                }

                size_t remaining = ftell(image_file) - (file_pos + strlen(known_signatures[i].signature));
                unsigned char *data = malloc(remaining);
                fseek(image_file, file_pos + strlen(known_signatures[i].signature), SEEK_SET);
                fread(data, 1, remaining, image_file);
                fwrite(data, 1, remaining, carved_file);
                free(data);
                fclose(carved_file);
            }
        }

        file_pos += bytes_read;
    }

    fclose(image_file);
    return 0;
}