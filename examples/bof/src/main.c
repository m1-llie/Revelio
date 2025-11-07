#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void copy_message(const char *input) {
    char buffer[32];
    strcpy(buffer, input);
    printf("Copied input: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return EXIT_FAILURE;
    }

    copy_message(argv[1]);
    printf("Message processed.\n");
    return EXIT_SUCCESS;
}
