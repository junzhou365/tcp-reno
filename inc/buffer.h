#ifndef _BUFFER_H_
#define _BUFFER_H_

typedef struct {
    int cap;
    char *data;

    int len;
} buffer;

buffer *new_buffer(int cap);
void buffer_free(buffer *b);

int buffer_cap(buffer *b);
int buffer_len(buffer *b);

void buffer_from_data(buffer *b, char *data, int len);

int buffer_write(buffer *b, char *data, int len);
void buffer_sub_buffer(buffer *b, int s, buffer *buf_out);
void buffer_subrange_buffer(buffer *b, int s, int e, buffer *buf_out);
char *buffer_data(buffer *b);

#define ERR_BUFFER_FULL 1
#define ERR_BUFFER_EMPTY 2
#define ERR_BUFFER_NO_ENOUGH_SPACE 3

#endif
