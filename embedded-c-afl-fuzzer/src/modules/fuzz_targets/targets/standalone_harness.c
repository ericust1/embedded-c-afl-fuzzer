#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int parse_protocol_message(const unsigned char *buf, size_t buf_len);
extern int process_records(const unsigned char *buf, size_t buf_len);
extern int parse_image(const unsigned char *buf, size_t buf_len);

static unsigned char input_buf[8192];

int main(int argc, char **argv) {
    ssize_t n;
    FILE *f;
    const char *mode;
    int target_id = 0;

    if (argc > 1) {
        if (strcmp(argv[1], "--target") == 0 && argc > 2) {
            target_id = atoi(argv[2]);
        } else {
            f = fopen(argv[1], "rb");
            if (!f) {
                fprintf(stderr, "Cannot open %s\n", argv[1]);
                return 1;
            }
            n = fread(input_buf, 1, sizeof(input_buf), f);
            fclose(f);
            goto run;
        }
    }

    if (argc > 3) {
        f = fopen(argv[3], "rb");
        if (!f) {
            fprintf(stderr, "Cannot open %s\n", argv[3]);
            return 1;
        }
        n = fread(input_buf, 1, sizeof(input_buf), f);
        fclose(f);
    } else {
        n = read(STDIN_FILENO, input_buf, sizeof(input_buf));
        if (n < 0) {
            return 1;
        }
    }

run:
    switch (target_id) {
        case 1:
            parse_protocol_message(input_buf, (size_t)n);
            break;
        case 2:
            process_records(input_buf, (size_t)n);
            break;
        case 3:
            parse_image(input_buf, (size_t)n);
            break;
        default:
            parse_protocol_message(input_buf, (size_t)n);
            process_records(input_buf, (size_t)n);
            parse_image(input_buf, (size_t)n);
            break;
    }

    return 0;
}