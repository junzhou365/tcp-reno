#include <stdlib.h>
#include <stdio.h>
#include "buffer.h"

buffer *new_buffer(int cap) {
    buffer* new =  malloc(sizeof(buffer));
    new->data = malloc(cap);
    new->cap = cap;
    new->len = 0;
    return new;
}

void buffer_free(buffer *b) {
    free(b->data);
    free(b);
}

int buffer_cap(buffer *b) {
    return b->cap;
}

int buffer_len(buffer *b) {
    return b->len;
}

void buffer_from_data(buffer *b, char *data, int len) {
    b->data = data;
    b->len = len;
    b->cap = len;
}

int buffer_write(buffer *b, char *data, int len) {
    if (len > (b->cap - b->len))
        return ERR_BUFFER_NO_ENOUGH_SPACE;

    int j = b->len;
    for (int i = 0; i < len; i++) {
        b->data[j] = data[i];
        j++;
    }

    b->len = j;
    b->cap -= len;

    return 0;
}

void buffer_sub_buffer(buffer *b, int s, buffer *buf_out) {
    buffer_subrange_buffer(b, s, b->len, buf_out);
}

void buffer_subrange_buffer(buffer *b, int s, int e, buffer *buf_out) {
    if (s >= e) {
        return;
    }

    if (b->len <= s) {
        return;
    } 

    if (e > b->len) {
        e = b->len;
    }

    buf_out->data = b->data + s;
    buf_out->len = e - s;

    /* -----------|xxxxx */
    buf_out->cap = b->cap;
}

char *buffer_data(buffer *b) {
    return b->data;
}
