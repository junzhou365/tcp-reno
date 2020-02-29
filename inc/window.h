#ifndef _WINDOW_H_
#define _WINDOW_H_

#include "ringbuffer.h"

typedef struct {
	uint32_t cur_seq;
	uint32_t last_ack_received;
	uint32_t last_win_received;
	pthread_mutex_t ack_lock;

    //ringbuffer* sndq;
} send_window_t;

typedef struct {
	uint32_t last_seq_received;

    ringbuffer* rcvq;
} recv_window_t;


#endif
