#ifndef _LOGGER_H_
#define _LOGGER_H_
#include <stdarg.h>
#include <stdio.h>

#define DEBUG_LEVEL 1
#define INFO_LEVEL  2

#define LEVEL DEBUG_LEVEL

void log_debugf(const char *fmt, ...) {
    if (LEVEL != DEBUG_LEVEL) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

#endif
