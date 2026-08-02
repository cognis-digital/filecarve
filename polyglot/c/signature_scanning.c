#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define MAX_SIGNATURES 1024
#define MAX_SIGNATURE_LEN 1024
#define BUFFER_SIZE 65536

typedef struct {
    char *signature;
    size_t len;
    char *description;
} Signature;

Signature signatures[MAX_SIGNATURES];
size_t num_signatures = 0;

void load_signatures(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open signature file");
        exit(EXIT_FAILURE);
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#') continue;

        char *desc = strchr(line, '\t');
        if (!desc) continue;

        *desc++ = '\0';
        desc = strchr(desc, '\t');
        if (!desc) continue;

        *desc++ = '\0';
        char *sig = line;
        size_t len = strlen(sig);

        if (len > MAX_SIGNATURE_LEN) continue;

        signatures[num_signatures].signature = strdup(sig);
        signatures[num_signatures].len = len;
        signatures[num_signatures].description = strdup(desc);

        num_signatures++;
    }

    fclose(fp);
}

void carve_files(int fd, const char *output_dir) {
    if (mkdir(output_dir, 0777) == -1 && errno != EEXIST) {
        perror("Failed to create output directory");
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    int file_count = 0;

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        for (size_t i = 0; i < num_signatures && i + signatures[i].len <= bytes_read; i++) {
            size_t match = 0;
            while (match < signatures[i].len) {
                if (buffer[i + match] != signatures[i].signature[match]) break;
                match++;
            }

            if (match == signatures[i].len) {
                char filename[256];
                snprintf(filename, sizeof(filename), "%s/%s_%d", output_dir, signatures[i].description, file_count++);
                FILE *out = fopen(filename, "wb");
                if (!out) {
                    perror("Failed to open output file");
                    continue;
                }

                size_t offset = i;
                while (offset < bytes_read) {
                    size_t remaining = bytes_read - offset;
                    size_t to_copy = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;
                    fwrite(buffer + offset, 1, to_copy, out);
                    offset += to_copy;
                }

                fclose(out);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <signature_file> <input_image> <output_dir>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *sig_file = argv[1];
    const char *input_file = argv[2];
    const char *output_dir = argv[3];

    load_signatures(sig_file);

    int fd = open(input_file, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open input file");
        return EXIT_FAILURE;
    }

    carve_files(fd, output_dir);

    close(fd);
    return EXIT_SUCCESS;
}