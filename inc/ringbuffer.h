#ifndef _RINGBUFFER_H_
#define _RINGBUFFER_H_

typedef struct {
    int cap;
    char *data;

    int len;
    int start;
    int end;
} ringbuffer;

ringbuffer *new_ringbuffer(int cap);
void ringbuffer_free(ringbuffer *rb);

int ringbuffer_cap(ringbuffer *rb);
int ringbuffer_len(ringbuffer *rb);
int ringbuffer_push(ringbuffer *rb, char *data, int len);
int ringbuffer_pop(ringbuffer *rb, char **data_out, int len);

int ringbuffer_insert(ringbuffer *rb, int offset, char *data, int len);
int ringbuffer_move_end(ringbuffer *rb, int len);

#define ERR_RINGBUFFER_FULL 1
#define ERR_RINGBUFFER_EMPTY 2
#define ERR_RINGBUFFER_NO_ENOUGH_SPACE 3

#endif

