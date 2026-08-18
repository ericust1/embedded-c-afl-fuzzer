#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PAYLOAD 64

typedef struct {
    unsigned short type;
    unsigned short length;
    unsigned char data[MAX_PAYLOAD];
} protocol_header_t;

int parse_protocol_message(const unsigned char *buf, size_t buf_len) {
    protocol_header_t header;
    unsigned short msg_type;
    unsigned short msg_length;

    if (buf_len < 4) {
        return -1;
    }

    msg_type = (buf[0] << 8) | buf[1];
    msg_length = (buf[2] << 8) | buf[3];

    if (msg_type == 0x0001) {
        if (buf_len < 4 + msg_length) {
            return -1;
        }
        memcpy(header.data, buf + 4, msg_length);
        header.data[msg_length] = '\0';
        return 0;
    } else if (msg_type == 0x0002) {
        unsigned char local_buf[MAX_PAYLOAD];
        if (buf_len < 4 + msg_length) {
            return -1;
        }
        memcpy(local_buf, buf + 4, msg_length);
        local_buf[msg_length] = '\0';
        printf("Processed type 0x0002, payload: %s\n", local_buf);
        return 0;
    }

    return -1;
}

#ifndef BUILDING_HARNESS
int main(int argc, char **argv) {
    unsigned char input[4096];
    ssize_t n;
    FILE *f;

    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            return 1;
        }
        n = fread(input, 1, sizeof(input), f);
        fclose(f);
    } else {
        n = read(STDIN_FILENO, input, sizeof(input));
        if (n < 0) {
            return 1;
        }
    }

    parse_protocol_message(input, (size_t)n);
    return 0;
}
#endif
