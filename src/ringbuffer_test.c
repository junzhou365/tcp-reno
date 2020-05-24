#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ringbuffer.h"

int test_new_ringbuffer() {
    ringbuffer *rb = new_ringbuffer(10);
    assert(rb != 0);
    assert(rb->cap == 10);
    assert(rb->len == 0);
    ringbuffer_free(rb);
    return 0;
}

int test_ringbuffer_push_pop() {
    ringbuffer *rb = new_ringbuffer(2);

    char d1[1] = {0};
    char d2[1] = {1};
    char d3[1] = {2};

    int ret;

    ret = ringbuffer_push(rb, d1, 1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 1);

    ret = ringbuffer_push(rb, d2, 1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 2);

    char *data = malloc(1);
    
    ret = ringbuffer_pop(rb, &data, 1);
    assert(ret == 0);
    assert(data[0] == 0);


    ret = ringbuffer_push(rb, d3, 1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 2);

    ret = ringbuffer_pop(rb, &data, 1);
    assert(ret == 0);
    assert(data[0] == 1);
    assert(ringbuffer_len(rb) == 1);

    ret = ringbuffer_pop(rb, &data, 1);
    assert(ret == 0);
    assert(data[0] == 2);
    assert(ringbuffer_len(rb) == 0);

    ringbuffer_free(rb);
    free(data);
    return 0;
}

int test_ringbuffer_insert_move() {
    ringbuffer *rb = new_ringbuffer(2);

    char d1[1] = {0};
    char d2[1] = {1};
    char d3[1] = {2};

    int ret;

    ret = ringbuffer_insert(rb, 0, d1, 1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 0);

    ret = ringbuffer_insert(rb, 1, d2, 1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 0);

    ret = ringbuffer_insert(rb, 1, d3, 1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 0);

    ret = ringbuffer_move_end(rb, 1);
    assert(ret == 0);


    char *data = malloc(1);
    
    ret = ringbuffer_pop(rb, &data, 1);
    assert(ret == 0);
    assert(data[0] == 0);
    assert(ringbuffer_len(rb) == 0);

    ret = ringbuffer_move_end(rb, 1);
    assert(ret == 0);

    ret = ringbuffer_pop(rb, &data, 1);
    assert(ret == 0);
    assert(data[0] == 2);
    assert(ringbuffer_len(rb) == 0);

    ringbuffer_free(rb);
    free(data);
    return 0;
}

int test_ringbuffer_peek() {
    ringbuffer *rb = new_ringbuffer(2);

    char d1[1] = {1};
    char d2[1] = {2};

    int ret;

    ret = ringbuffer_push(rb, d1, 1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 1);

    ret = ringbuffer_push(rb, d2, 1);
    assert(ret == 0);
    assert(ringbuffer_len(rb) == 2);

    char *data = malloc(2);
    int rlen = 0;

    ret = ringbuffer_peek_from_start_offset(rb, 2, 1, &data, &rlen);
    assert(ret == 0);
    assert(rlen == 1);
    assert(data[0] == 2);

    memset(data, 0, 2);
    ret = ringbuffer_peek_from_start_offset(rb, 1, 0, &data, &rlen);
    assert(ret == 0);
    assert(rlen == 1);
    assert(data[0] == 1);

    memset(data, 0, 2);
    ret = ringbuffer_peek_from_start_offset(rb, 2, 0, &data, &rlen);
    assert(ret == 0);
    assert(rlen == 2);
    assert(data[0] == 1);
    assert(data[1] == 2);

    free(data);

    return 0;
}


int main() {
    int ret;

    ret = test_new_ringbuffer();
    if (ret == 0)
        printf("new rb succeed!!\n");

    ret = test_ringbuffer_push_pop();
    if (ret == 0)
        printf("push pop succeed!!\n");

    ret = test_ringbuffer_insert_move();
    if (ret == 0)
        printf("push pop succeed!!\n");

    ret = test_ringbuffer_peek();
    if (ret == 0)
        printf("peek succeed!!\n");

    return 0;
}
