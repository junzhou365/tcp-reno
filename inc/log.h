#ifndef _LOGGER_H_
#define _LOGGER_H_

#define DEBUG_LEVEL 1
#define INFO_LEVEL  2
#define ERROR_LEVEL  3

//#define LEVEL INFO_LEVEL
#define LEVEL DEBUG_LEVEL

void log_debugf(const char *fmt, ...);
void log_infof(const char *fmt, ...);

#endif
