#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_SIGNATURES 100
#define MAX_SIGNATURE_LENGTH 1024
#define MAX_DESCRIPTION_LENGTH 256

typedef struct {
    char signature[MAX_SIGNATURE_LENGTH];
    char description[MAX_DESCRIPTION_LENGTH];
} Signature;

typedef struct {
    int count;
    Signature signatures[MAX_SIGNATURES];
} SignatureDatabase;

void load_signatures(SignatureDatabase *db, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error opening signature file: %s\n", filename);
        return;
    }

    db->count = 0;
    char line[MAX_SIGNATURE_LENGTH];

    while (fgets(line, sizeof(line), file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || !strlen(line)) continue;

        // Split into signature and description
        char *desc_start = strchr(line, '\t');
        if (!desc_start) {
            desc_start = strchr(line, ' ');
        }

        if (desc_start) {
            *desc_start = '\0';
            desc_start++;
            strncpy(db->signatures[db->count].signature, line, MAX_SIGNATURE_LENGTH - 1);
            strncpy(db->signatures[db->count].description, desc_start, MAX_DESCRIPTION_LENGTH - 1);
            db->count++;
        } else {
            strncpy(db->signatures[db->count].signature, line, MAX_SIGNATURE_LENGTH - 1);
            strcpy(db->signatures[db->count].description, "No description");
            db->count++;
        }

        if (db->count >= MAX_SIGNATURES) {
            fprintf(stderr, "Signature database full.\n");
            break;
        }
    }

    fclose(file);
}

void print_signatures(SignatureDatabase *db) {
    printf("Available Signatures:\n");
    for (int i = 0; i < db->count; i++) {
        printf("%-30s %s\n", db->signatures[i].signature, db->signatures[i].description);
    }
}

int main() {
    SignatureDatabase db;
    load_signatures(&db, "signatures.txt");

    if (db.count == 0) {
        fprintf(stderr, "No signatures loaded.\n");
        return 1;
    }

    print_signatures(&db);

    // Example: Search for a signature
    char search_sig[MAX_SIGNATURE_LENGTH];
    printf("\nEnter a signature to search: ");
    scanf("%s", search_sig);

    int found = 0;
    for (int i = 0; i < db.count; i++) {
        if (strcmp(db.signatures[i].signature, search_sig) == 0) {
            printf("Found signature: %s - %s\n", db.signatures[i].signature, db.signatures[i].description);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("Signature not found.\n");
    }

    return 0;
}