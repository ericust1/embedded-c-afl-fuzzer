#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    unsigned int id;
    unsigned short name_len;
    unsigned short data_len;
    char *name;
    char *data;
} record_t;

record_t *create_record(const unsigned char *buf, size_t buf_len) {
    record_t *rec;

    if (buf_len < 8) {
        return NULL;
    }

    rec = (record_t *)malloc(sizeof(record_t));
    if (!rec) {
        return NULL;
    }
    memset(rec, 0, sizeof(record_t));

    rec->id = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    rec->name_len = (buf[4] << 8) | buf[5];
    rec->data_len = (buf[6] << 8) | buf[7];

    if (buf_len < 8 + rec->name_len + rec->data_len) {
        free(rec);
        return NULL;
    }

    rec->name = (char *)malloc(rec->name_len);
    if (!rec->name) {
        free(rec);
        return NULL;
    }
    memcpy(rec->name, buf + 8, rec->name_len);

    rec->data = (char *)malloc(rec->data_len);
    if (!rec->data) {
        free(rec->name);
        free(rec);
        return NULL;
    }
    memcpy(rec->data, buf + 8 + rec->name_len, rec->data_len);

    return rec;
}

int process_records(const unsigned char *buf, size_t buf_len) {
    record_t *records[4];
    int count = 0;
    size_t offset = 0;
    unsigned short name_len, data_len;

    while (count < 4 && offset < buf_len) {
        if (buf_len - offset < 4) {
            break;
        }

        name_len = (buf[offset] << 8) | buf[offset + 1];
        data_len = (buf[offset + 2] << 8) | buf[offset + 3];
        offset += 4;

        if (buf_len - offset < name_len + data_len) {
            break;
        }

        records[count] = create_record(buf + offset - 4, 4 + name_len + data_len);
        if (records[count]) {
            count++;
        }
        offset += name_len + data_len;
    }

    if (count >= 2) {
        free(records[1]->data);
        free(records[1]->name);
        free(records[1]);
        records[1] = NULL;

        if (count >= 3 && records[2]) {
            free(records[2]->name);
            free(records[2]);
            records[2] = NULL;
        }
    }

    for (int i = 0; i < count; i++) {
        if (records[i]) {
            if (records[i]->data) free(records[i]->data);
            if (records[i]->name) free(records[i]->name);
            free(records[i]);
        }
    }

    return count;
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

    process_records(input, (size_t)n);
    return 0;
}
#endif