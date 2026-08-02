#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAX_SIGNATURES 10
#define MAX_FILE_NAME 256
#define BUFFER_SIZE 4096

typedef struct {
    char *signature;
    char *file_type;
} SignatureEntry;

// Sample signatures for common file types
SignatureEntry signatures[] = {
    {"\x50\x4b\x03\x04", "ZIP"},
    {"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "MS Office (DOCX)"},
    {"\x25\x50\x44\x46", "PDF"},
    {"\x49\x49\x2A\x00", "TIFF"},
    {"\x42\x4D", "Windows Bitmap"},
    {"\x52\x61\x72\x21\x19\x00\x01\x00", "RAR"},
    {"\x47\x49\x46\x38", "GIF"},
    {"\x49\x49\x43\x4D", "PNG"},
    {"\xFF\xD8\xFF", "JPEG"},
    {"\x50\x4B\x01\x02", "ZIP (streamed)"}
};

int find_signature(const unsigned char *buffer, size_t size) {
    for (int i = 0; i < MAX_SIGNATURES; i++) {
        if (size >= strlen(signatures[i].signature)) {
            if (memcmp(buffer, signatures[i].signature, strlen(signatures[i].signature)) == 0) {
                return i;
            }
        }
    }
    return -1;
}

void carve_files_from_image(const char *image_path, const char *output_dir) {
    int fd = open(image_path, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open image");
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    char file_name[MAX_FILE_NAME];
    int file_count = 0;

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        int sig_idx = find_signature(buffer, bytes_read);
        if (sig_idx != -1) {
            snprintf(file_name, MAX_FILE_NAME, "%s_%d.%s", output_dir, file_count++, signatures[sig_idx].file_type);
            FILE *out_file = fopen(file_name, "wb");
            if (!out_file) {
                perror("Failed to create output file");
                continue;
            }

            // Write the matched signature and subsequent data
            fwrite(buffer, 1, bytes_read, out_file);
            fclose(out_file);
        }
    }

    close(fd);
    printf("Carved %d files.\n", file_count);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <image_path> <output_dir>\n", argv[0]);
        return 1;
    }

    const char *image_path = argv[1];
    const char *output_dir = argv[2];

    // Create output directory if it doesn't exist
    if (mkdir(output_dir, 0777) == -1 && errno != EEXIST) {
        perror("Failed to create output directory");
        return 1;
    }

    carve_files_from_image(image_path, output_dir);

    return 0;
}