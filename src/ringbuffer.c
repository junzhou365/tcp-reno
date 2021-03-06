#include <stdlib.h>
#include <stdio.h>
#include "ringbuffer.h"

ringbuffer *new_ringbuffer(int cap) {
    ringbuffer* new =  malloc(sizeof(ringbuffer));
    new->data = malloc(cap);
    new->cap = cap;
    new->start = 0;
    new->end = 0;
    new->len = 0;
    return new;
}

void ringbuffer_free(ringbuffer *rb) {
    free(rb->data);
    free(rb);
}

int ringbuffer_cap(ringbuffer *rb) {
    return rb->cap;
}

int ringbuffer_len(ringbuffer *rb) {
    return rb->len;
}

int ringbuffer_free_space(ringbuffer *rb) {
    return rb->cap - rb->len;
}

int ringbuffer_push(ringbuffer *rb, char *data, int len) {
    if (len > (rb->cap - rb->len))
        return ERR_RINGBUFFER_NO_ENOUGH_SPACE;

    for (int i = 0; i < len; i++) {
        rb->data[rb->end] = data[i];
        rb->end = (rb->end + 1) % rb->cap;
    }
    rb->len += len;

    return 0;
}

int ringbuffer_pop(ringbuffer *rb, char **data_out, int len) {
    if (rb->len == 0)
        return ERR_RINGBUFFER_EMPTY;

    for (int i = 0; i < len; i++) {
        if (data_out != NULL) {
            *(*data_out + i) = rb->data[rb->start];
        }
        rb->start = (rb->start + 1) % rb->cap; 
    }

    rb->len -= len;
    return 0;
}

int ringbuffer_insert(ringbuffer *rb, int offset, char *data, int len) {
    if ((offset + len) > (rb->cap - rb->len))
        return ERR_RINGBUFFER_NO_ENOUGH_SPACE;

    int next = (rb->end + offset) % rb->cap;
    for (int i = 0; i < len; i++) {
        rb->data[next] = data[i];
        next = (next + 1) % rb->cap;
    }

    return 0;
}

int ringbuffer_move_end(ringbuffer *rb, int len) {
    if (len > (rb->cap - rb->len))
        return ERR_RINGBUFFER_NO_ENOUGH_SPACE;

    rb->end = (rb->end + len) % rb->cap;
    rb->len += len;
    return 0;
}

int ringbuffer_peek_from_start_offset(
        ringbuffer *rb, int len, int offset, char **data_out, int *len_out) {

    int peek_len = 0;
    int rlen = rb->len - offset;
    int start = (rb->start + offset) % rb->cap;
    for (int i = 0; i < len && i < rlen; i++) {
        *(*data_out + i) = rb->data[start];
        peek_len++;
        start = (start + 1) % rb->cap;
    }

    *len_out = peek_len;
    return 0;
}

int ringbuffer_peek_from_start(
        ringbuffer *rb, int len, char **data_out, int *len_out) {
    return ringbuffer_peek_from_start_offset(rb, len, 0, data_out, len_out);
}
