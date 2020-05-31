#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "timer.h"

int test_new_timer() {
    tcp_timer_t *t = new_tcp_timer(10, 10);

    assert(t->cap == 10);
    assert(t->est_rtt == 10 * 1000);

    tcp_timer_free(t);
    return 0;
}

int test_timer_track() {
    int ret;
    tcp_timer_t *t = new_tcp_timer(100000, 1);

    {
        timer_start_track(t, 0, 1000);
        timer_start_track(t, 1000, 1000);
        timer_start_track(t, 2000, 1000);
        timer_start_track(t, 3000, 1000);

        sleep(1);

        int t1, t2;

        ret = timer_end_track(t, 1000);
        assert(ret == 0);
        t1 = t->timeout;
        printf("t1 timeout: %d\n", t1);

        ret = timer_end_track(t, 2000);
        assert(ret == 0);
        t2 = t->timeout;
        printf("t2 timeout: %d\n", t2);

        ret = timer_end_track(t, 3000);
        assert(ret == 0);
        t2 = t->timeout;
        printf("t2 timeout: %d\n", t2);

        ret = timer_end_track(t, 4000);
        assert(ret == 0);
        t2 = t->timeout;
        printf("t2 timeout: %d\n", t2);

        assert(t1 != t2);
    }

    {
        timer_start_track(t, 0, 1000);
        timer_start_track(t, 1000, 1000);

        sleep(1);

        ret = timer_end_track(t, 1000);
        assert(ret == 0);
        int t1 = t->timeout;
        printf("t1 timeout: %d\n", t1);

        ret = timer_end_track(t, 2000);
        assert(ret == 0);
        int t2 = t->timeout;
        printf("t2 timeout: %d\n", t2);

        assert(t1 != t2);
    }

    {

        for (int i = 0; i < 128; i++) {
            if (i % 7 == 2) {
                timer_start_track(t, i * 1000, 1000);
            } 
        }

        sleep(1);

        for (int i = 0; i < 128; i++) {
            timer_end_track(t, 1000 * (i+1));
        }

    }

    tcp_timer_free(t);
    return 0;
}

int main() {
    int ret;

    ret = test_new_timer();
    assert(ret == 0);
    printf("test_new_timer succeeds!!!\n");

    ret = test_timer_track();
    assert(ret == 0);
    printf("test_timer_track succeeds!!!\n");
    return 0;
}
