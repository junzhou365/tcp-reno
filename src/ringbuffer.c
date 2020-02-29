#include <stdlib.h>
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

int ringbuffer_push(ringbuffer *rb, char *data, int len) {
    if (rb->len == rb->cap)
        return ERR_RINGBUFFER_FULL;

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
