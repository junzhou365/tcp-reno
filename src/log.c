#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

void log_printf(const char *fmt, ...) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    printf("%lld.%.6ldz: ", (long long)ts.tv_sec, ts.tv_nsec/1000);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void log_debugf(const char *fmt, ...) {
    if (LEVEL > DEBUG_LEVEL) {
        return;
    }

    log_printf(fmt);
}

void log_infof(const char *fmt, ...) {
    if (LEVEL > INFO_LEVEL) {
        return;
    }

    log_printf(fmt);
}
