#ifndef _WINDOW_H_
#define _WINDOW_H_

#include "ringbuffer.h"
#include "timer.h"

#define CONG_SLOW_START     0
#define CONG_AVOID          1
#define CONG_RECOV          2

typedef struct {
	uint32_t last_ack_received;
	uint32_t last_win_received;
    uint32_t last_byte_sent;
	pthread_mutex_t ack_lock;

    ringbuffer* sendq;

    int duplicates;

    int cwnd;
    int ssthresh;
    int cong_state;
    tcp_timer_t *timer;

} send_window_t;

typedef struct {
	uint32_t last_seq_received;
	uint32_t next_exp_byte;
    uint32_t last_byte_read;

    ringbuffer* recvq;
} recv_window_t;


#endif
