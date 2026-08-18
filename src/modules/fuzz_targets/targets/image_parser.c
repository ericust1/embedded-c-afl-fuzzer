#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char magic[4];
    unsigned short width;
    unsigned short height;
    unsigned char bpp;
    unsigned char reserved;
} image_header_t;

int parse_image(const unsigned char *buf, size_t buf_len) {
    image_header_t hdr;
    unsigned long pixel_size;
    unsigned char *pixels;
    int i;

    if (buf_len < sizeof(image_header_t)) {
        return -1;
    }

    memcpy(&hdr, buf, sizeof(image_header_t));

    if (memcmp(hdr.magic, "IMGF", 4) != 0) {
        return -1;
    }

    if (hdr.bpp != 1 && hdr.bpp != 3 && hdr.bpp != 4) {
        return -1;
    }

    pixel_size = (unsigned long)hdr.width * (unsigned long)hdr.height * (unsigned long)hdr.bpp;

    if (pixel_size > 16 * 1024 * 1024) {
        return -1;
    }

    pixels = (unsigned char *)malloc(pixel_size);
    if (!pixels) {
        return -1;
    }

    if (buf_len - sizeof(image_header_t) < pixel_size) {
        memcpy(pixels, buf + sizeof(image_header_t), buf_len - sizeof(image_header_t));
    } else {
        memcpy(pixels, buf + sizeof(image_header_t), pixel_size);
    }

    for (i = 0; i < (int)(pixel_size > 16 ? 16 : pixel_size); i++) {
        pixels[i] = pixels[i] ^ 0xFF;
    }

    free(pixels);
    return 0;
}

#ifndef BUILDING_HARNESS
int main(int argc, char **argv) {
    unsigned char input[4096];
    ssize_t n;
    FILE *f;

    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) return 1;
        n = fread(input, 1, sizeof(input), f);
        fclose(f);
    } else {
        n = read(STDIN_FILENO, input, sizeof(input));
        if (n < 0) return 1;
    }

    parse_image(input, (size_t)n);
    return 0;
}
#endif
