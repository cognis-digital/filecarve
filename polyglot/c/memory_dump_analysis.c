#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define MAX_SIGNATURES 10
#define MAX_SIG_LEN 256

typedef struct {
    char *signature;
    char *description;
} Signature;

// Sample known memory dump signatures
Signature known_signatures[] = {
    {"\x00\x00\x01\x00", "NTFS Master File Table (MFT) start"},
    {"\x53\x46\x45\x52", "SFER - Filesystem signature (e.g., FAT)"},
    {"\x49\x49\x2A\x00", "TIFF image file"},
    {"\x4D\x44\x41\x54", "MDAT - MPEG-4 audio/video data"},
    {"\x42\x4D", "BM - Windows bitmap file"}
};

// Function to check if a signature is present in the buffer
int contains_signature(const unsigned char *buffer, size_t size, const char *signature) {
    size_t sig_len = strlen(signature);
    if (sig_len > size) return 0;

    for (size_t i = 0; i <= size - sig_len; i++) {
        int match = 1;
        for (size_t j = 0; j < sig_len; j++) {
            if (buffer[i + j] != signature[j]) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

// Function to find and report all matching signatures in the buffer
void find_signatures(const unsigned char *buffer, size_t size) {
    printf("Memory dump signature analysis:\n");
    for (int i = 0; i < MAX_SIGNATURES; i++) {
        if (contains_signature(buffer, size, known_signatures[i].signature)) {
            printf(" - Found: %s (%s)\n", known_signatures[i].signature, known_signatures[i].description);
        }
    }
}

// Function to read a file into memory
unsigned char *read_file(const char *filename, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = (unsigned char *)malloc(*size);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(file);
        return NULL;
    }

    size_t read = fread(buffer, 1, *size, file);
    if (read != *size) {
        perror("Failed to read file");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

// Main entry point
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <memory_dump_file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    size_t file_size;
    unsigned char *buffer = read_file(filename, &file_size);

    if (!buffer) {
        return 1;
    }

    find_signatures(buffer, file_size);
    free(buffer);
    return 0;
}