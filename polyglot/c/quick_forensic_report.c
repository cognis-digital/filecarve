#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_FILE_NAME_LEN 256
#define MAX_SIGNATURE_LEN 1024
#define MAX_REPORT_LINES 1000

typedef struct {
    char name[MAX_FILE_NAME_LEN];
    char signature[MAX_SIGNATURE_LEN];
    size_t offset;
    size_t size;
} FileEntry;

void print_report(FileEntry *entries, int count) {
    printf("=== Quick Forensic Report ===\n");
    for (int i = 0; i < count; i++) {
        printf("Found file: %s\n", entries[i].name);
        printf("  Signature: %s\n", entries[i].signature);
        printf("  Offset: %zu bytes\n", entries[i].offset);
        printf("  Size: %zu bytes\n", entries[i].size);
        printf("----------------------------\n");
    }
    printf("=== End of Report ===\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <image_file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("Failed to open image file");
        return 1;
    }

    FileEntry entries[MAX_REPORT_LINES];
    int entry_count = 0;

    // Example signatures and files (simulated for demo)
    const char *signatures[] = {
        "\x50\x4b\x03\x04",      // ZIP
        "\x49\x49\x2A\x00",      // JPEG
        "\x4D\x5A\x90\x00",      // PE (Windows EXE)
        "\x52\x61\x72\x21",      // RAR
        "\x47\x49\x46\x38",      // GIF
        "\x89\x50\x4E\x47",      // PNG
        "\x42\x4D",              // BMP
        "\x00\x00\x01\xBA",      // FAT32 boot sector
        "\x55\xAA",              // MBR signature
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // Example custom signature
    };

    const char *file_names[] = {
        "ZIP File",
        "JPEG Image",
        "Windows EXE",
        "RAR Archive",
        "GIF Image",
        "PNG Image",
        "BMP Image",
        "FAT32 Boot Sector",
        "MBR Signature",
        "Custom File"
    };

    // Simulate scanning the image for known signatures
    fseek(file, 0, SEEK_SET);
    unsigned char buffer[16];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (int i = 0; i < sizeof(signatures) / sizeof(signatures[0]); i++) {
            if (bytes_read >= strlen(signatures[i])) {
                int match = 1;
                for (size_t j = 0; j < strlen(signatures[i]); j++) {
                    if (buffer[j] != signatures[i][j]) {
                        match = 0;
                        break;
                    }
                }
                if (match) {
                    if (entry_count < MAX_REPORT_LINES) {
                        strncpy(entries[entry_count].name, file_names[i], MAX_FILE_NAME_LEN);
                        strncpy(entries[entry_count].signature, signatures[i], MAX_SIGNATURE_LEN);
                        entries[entry_count].offset = ftell(file) - bytes_read;
                        entries[entry_count].size = 0; // Size not determined in this demo
                        entry_count++;
                    }
                }
            }
        }
    }

    fclose(file);

    print_report(entries, entry_count);

    return 0;
}