#include <stdlib.h>
#include "ringbuffer.h"

ringbuffer *new_ringbuffer(int cap) {
    ringbuffer* new =  malloc(sizeof(ringbuffer));
    new->packets = malloc(cap);
    new->cap = cap;
    new->start = 0;
    new->end = 0;
    new->len = 0;
    return new;
}

void ringbuffer_free(ringbuffer *rb) {
    free(rb->packets);
    free(rb);
}

int ringbuffer_cap(ringbuffer *rb) {
    return rb->cap;
}

int ringbuffer_len(ringbuffer *rb) {
    return rb->len;
}

int ringbuffer_push(ringbuffer *rb, cmu_packet_t *pkt) {
    if (rb->len == rb->cap)
        return ERR_RINGBUFFER_FULL;

    rb->packets[rb->end] = pkt;
    rb->end = (rb->end + 1) % rb->cap;
    rb->len++;

    return 0;
}

int ringbuffer_pop(ringbuffer *rb, cmu_packet_t **store) {
    if (rb->len == 0)
        return ERR_RINGBUFFER_EMPTY;

    *store = rb->packets[rb->start];
    rb->start = (rb->start + 1) % rb->cap; 
    rb->len--;

    return 0;
}
