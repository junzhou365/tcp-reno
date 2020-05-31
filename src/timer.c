#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "timer.h"
#include "log.h"


tcp_timer_t *new_tcp_timer(int initial_rtt_msec, int cap) {
    tcp_timer_t* new = malloc(sizeof(tcp_timer_t));
    new->deviation = 0;
    new->est_rtt = initial_rtt_msec * 1000;
    new->deviation = 0;
    new->timeout = initial_rtt_msec * 1000;
    new->largest_seq = 0;
    new->cap = cap;
    new->len = 0;
    new->start = 0;
    new->end = 0;
    new->ts_queue = malloc(cap * sizeof(ts_pair*));
    pthread_mutex_init(&(new->lock), NULL);
    return new;
}

void tcp_timer_free(tcp_timer_t *timer) {
    /*for (int i = 0; i < timer->len; i++) {*/
        /*free(timer->ts_queue[i+timer->start]);*/
    /*}*/
    free(timer->ts_queue);
    free(timer);
}

int get_curusec(struct timespec *ts) {
    return clock_gettime(CLOCK_REALTIME, ts);
}

long get_timeout(long est_rtt, long deviation) {
    return (est_rtt >> 3) + (deviation >> 1);
}

long diff_ts_usec(const struct timespec *now, const struct timespec *since) {
    long ret;
    double sec_diff = difftime(now->tv_sec, since->tv_sec);
    if (sec_diff > 0) {
        ret = ((long)(sec_diff - 1) * 1000000) + (1000000000L + now->tv_nsec - since->tv_nsec) / 1000;
    } else {
        assert(sec_diff == 0);
        ret = (now->tv_nsec - since->tv_nsec) / 1000;
    }

    /*log_debugf("diff_ts_usec: %d, sec_diff: %d\n", ret, sec_diff);*/
    assert(ret >= 0);
    return ret;
}

// sample_rtt is not scaled
// // est_rtt and deviation is scaled to 2^3
void update_rtts(int sample_rtt, long *est_rtt, long *deviation) {
    /*log_debugf("inital est_rtt: %d, dev: %d\n", *est_rtt, *deviation);*/
    sample_rtt -= (*est_rtt >> 3);
    *est_rtt += sample_rtt;
    if (sample_rtt < 0)
        sample_rtt = -sample_rtt;

    sample_rtt -= (*deviation >> 3);
    *deviation += sample_rtt;

    /*log_debugf("after sample_rtt: %d, est_rtt: %d, dev: %d\n", sample_rtt, *est_rtt, *deviation);*/
}

void timer_start_track(tcp_timer_t *timer, int seq, int len) {
    while(pthread_mutex_lock(&(timer->lock)) != 0);

    if (timer->largest_seq >= seq) {
        pthread_mutex_unlock(&(timer->lock));
        return;
    }

    timer->largest_seq = seq;

    if (timer->end >= timer->cap) {
        timer->cap = timer->cap * 2;
        timer->ts_queue = realloc(timer->ts_queue, timer->cap * sizeof(ts_pair*));

        for (int i = 0; i < timer->len; i++) {
            timer->ts_queue[i] = timer->ts_queue[i+timer->start];
        }
        timer->start = 0;
        timer->end = timer->len;
    }

    ts_pair *pair = malloc(sizeof(ts_pair));
    get_curusec(&(pair->ts));
    pair->seq = seq;
    pair->len = len;
    timer->ts_queue[timer->end] = pair;
    timer->len++;
    timer->end++;

    pthread_mutex_unlock(&(timer->lock));
}

int timer_end_track(tcp_timer_t *timer, int ack) {
    if (timer->len == 0)
        return -1;

    while(pthread_mutex_lock(&(timer->lock)) != 0);

    ts_pair *pair = timer->ts_queue[timer->start];

    if (ack < (pair->seq + pair->len)) {
        pthread_mutex_unlock(&(timer->lock));
        return -1;
    }

    struct timespec ts;
    get_curusec(&ts);

    long new_sample_rtt_usec = diff_ts_usec(&ts, &(pair->ts));
    assert(new_sample_rtt_usec > 0);

    update_rtts(
            new_sample_rtt_usec,
            &timer->est_rtt,
            &timer->deviation
            );
    timer->timeout = get_timeout(timer->est_rtt, timer->deviation);

    log_infof("timer: new timeout: %d for seq: %d, ack: %d\n",
            timer->timeout, pair->seq, ack);

    free(pair);
    timer->len--;
    timer->start++;

    if (timer->len == (timer->cap / 2)) {
        for (int i = 0; i < timer->len; i++) {
            timer->ts_queue[i] = timer->ts_queue[i+timer->start];
        }
        timer->start = 0;
        timer->end = timer->len;

        if (timer->cap / 2 > 0) {
            timer->ts_queue = realloc(timer->ts_queue, (timer->cap / 2) * sizeof(ts_pair*));
            timer->cap /= 2;
        }
    }

    pthread_mutex_unlock(&(timer->lock));
    return 0;
}

long timer_get_timeout(tcp_timer_t *timer) {
    return timer->timeout;
}
