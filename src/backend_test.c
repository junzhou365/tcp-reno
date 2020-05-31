#include <assert.h>
#include "backend.h"
#include "log.h"
#include "timer.h"

extern void multi_send(
    cmu_socket_t * sock, char *data, int len,
    ssize_t sendto_func(int, const void *, size_t, int, const struct sockaddr *, socklen_t)
);

extern int init_cmu_socket(cmu_socket_t * dst, int flag, int port);

int cnt = 0;

const int size = 32 << 10;

ssize_t mock_sendto(int a, const void * b, size_t c, int d, const struct sockaddr *e, socklen_t f) {
    ++cnt;
    printf("cnt is %d\n", cnt);
    if (cnt > 16 && (cnt % 2 == 1)) {
        return 0;
    }

    ssize_t ret = sendto(a, b, c, d, e, f);
    return ret;
}

static void *
start_recv(void *arg) {
    #undef MAX_NETWORK_BUFFER
    #define MAX_NETWORK_BUFFER 10

    cmu_socket_t sock;
    int ret = cmu_socket(&sock, TCP_LISTENER, 61234, "127.0.0.1");
    if (ret < 0) 
        return "error";

    printf("initialzed server socket\n");
    int send_size = size;
    while (size > 0) {
        char buf[1 << 10];
        int n = cmu_read(&sock, buf, send_size, NO_FLAG); 
        send_size -= n;
    }
    return NULL;
}


int new_recv(pthread_t *pid) {
    pthread_attr_t attr;
    int ret;
    ret = pthread_attr_init(&attr);
    if (ret < 0)
        exit(EXIT_FAILURE);

    ret = pthread_create(pid, &attr, &start_recv, NULL);
    if (ret < 0)
        exit(EXIT_FAILURE);

    return 0;
}

int test_from_zero_to_slow_start() {

    log_infof("starts now\n");

    int ret;

    pthread_t srv_pid;
    ret = new_recv(&srv_pid);
    if (ret < 0)
        return ret;

    cmu_socket_t sock;
    ret = cmu_socket(&sock, TCP_INITATOR, 61234, "127.0.0.1");
    if (ret < 0) 
        return ret;

    sock.sendto_func = mock_sendto;

    char *data;
    int buf_len = size;
    data = malloc(buf_len);

    cmu_write(&sock, data, buf_len);


    void *res;
    ret = pthread_join(srv_pid, &res);
    if (ret < 0)
        exit(EXIT_FAILURE);

    return 0;
}

/*
TEST-2
*/

extern void send_data_in_buffer(
	send_window_t *win,
	uint16_t my_port,
	uint16_t their_port,
    ssize_t sendto_func (int, const void *, size_t, int, const struct sockaddr *, socklen_t),
	int socket,
	struct sockaddr_in *conn,
    uint32_t new_first_byte,
    buffer *buf);

int send_data_buf_called;

ssize_t mock_sendto2(int a, const void * b, size_t c, int d, const struct sockaddr *e, socklen_t f) {
    send_data_buf_called++;
    return 0;
}


int test_send_data_in_buffer() {
    int len = 2000;
    buffer *buf = new_buffer(len);

    char *data = malloc(len);
    for (int i = 0; i < len; i++) {
        data[i] = i % 256;
    }

    buffer_write(buf, data, len);

    send_window_t win;
    win.timer = new_tcp_timer(0, 2);
    send_data_in_buffer(&win, 0, 0, mock_sendto2, 0, NULL, 0, buf);

    assert(send_data_buf_called == 2);
    assert(win.next_byte_to_send == len);

    free(data);

    return 0;
}

int test_get_send_buf_1() {
    int len = 10;
    buffer *buf = new_buffer(len);

    char *data = malloc(len);
    for (int i = 0; i < len; i++) {
        data[i] = i % 256;
    }

    buffer_write(buf, data, len);

    send_window_t win;
    win.sendq = buf;
    win.sendq_base = 20;
    win.last_ack_received = 20;
    win.last_win_received = 10;
    win.cwnd = 1000;

    buffer test_buf;
    get_send_buf(&win, 20, 0, &test_buf);

    int l = buffer_len(&test_buf);
    assert(l == 10);

    free(data);
}

int test_get_send_buf_2() {
    int len = 10;
    buffer *buf = new_buffer(len);

    char *data = malloc(len);
    for (int i = 0; i < len; i++) {
        data[i] = i % 256;
    }

    buffer_write(buf, data, len);

    send_window_t win;
    win.sendq = buf;
    win.sendq_base = 20;
    win.last_ack_received = 20;
    win.last_win_received = 10;
    win.cwnd = 1000;

    buffer test_buf;
    get_send_buf(&win, 20, 5, &test_buf);

    int l = buffer_len(&test_buf);
    assert(l == 5);

    free(data);
}


int main() {
    int ret;

    /*ret = test_from_zero_to_slow_start();*/
    /*if (ret == 0)*/
        /*printf("test_from_zero_to_slow_start succeeds!!\n");*/

    ret = test_send_data_in_buffer();
    if (ret == 0)
        printf("-- test_send_data_in_buffer succeeds!! --\n");

    ret = test_get_send_buf_1();
    if (ret == 0)
        printf("-- test_get_send_buf_1 succeeds!! --\n");

    ret = test_get_send_buf_2();
    if (ret == 0)
        printf("-- test_get_send_buf_2 succeeds!! --\n");

    return 0;
}
