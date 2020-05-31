#ifndef _TIMER_H_
#define _TIMER_H_

#include <pthread.h>
#include <time.h>

typedef struct {
    struct timespec ts;
    int seq;
    int len;
} ts_pair;

typedef struct {
    ts_pair **ts_queue;
    int cap;
    int len;
    int start;
    int end;

    long est_rtt; // the RTT in micro seconds, scaled
    long deviation; // in micro seconds, scaled
    long timeout; // in micro seconds
    long largest_seq;

	pthread_mutex_t lock;

} tcp_timer_t;

tcp_timer_t *new_tcp_timer(int initial_rtt_msec, int cap);
void tcp_timer_free(tcp_timer_t *timer);

void timer_start_track(tcp_timer_t *timer, int seq, int len);
int timer_end_track(tcp_timer_t *timer, int ack);
long timer_get_timeout(tcp_timer_t *timer);

int get_curusec(struct timespec *ts);
long diff_ts_usec(const struct timespec *now, const struct timespec *since);

#endif
