#include <assert.h>
#include <stdio.h>

#include "ringbuffer.h"

int test_new_ringbuffer() {
    ringbuffer *rb = new_ringbuffer(10);
    assert(rb != 0);
    assert(rb->cap == 10);
    assert(rb->len == 0);
    ringbuffer_free(rb);
    return 0;
}

int test_ringbuffer_pus_pop() {
    ringbuffer *rb = new_ringbuffer(2);

    cmu_packet_t pkt1 = {};
    pkt1.header.identifier = 1;
    cmu_packet_t pkt2 = {};
    pkt2.header.identifier = 2;
    cmu_packet_t pkt3 = {};
    pkt3.header.identifier = 3;

    int ret;

    ret = ringbuffer_push(rb, &pkt1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 1);

    ret = ringbuffer_push(rb, &pkt2);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 2);

    cmu_packet_t *pkt;
    
    ret = ringbuffer_pop(rb, &pkt);
    assert(ret == 0);
    assert(pkt->header.identifier == 1);


    ret = ringbuffer_push(rb, &pkt3);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 2);

    ret = ringbuffer_pop(rb, &pkt);
    assert(ret == 0);
    assert(pkt->header.identifier == 2);
    assert(ringbuffer_len(rb) == 1);

    ret = ringbuffer_pop(rb, &pkt);
    assert(ret == 0);
    assert(pkt->header.identifier == 3);
    assert(ringbuffer_len(rb) == 0);

    ringbuffer_free(rb);
    return 0;
}

int main() {
    int ret;

    ret = test_new_ringbuffer();
    if (ret == 0)
        printf("new rb succeed!!\n");

    ret = test_ringbuffer_pus_pop();
    if (ret == 0)
        printf("push pop succeed!!\n");
    return 0;
}
