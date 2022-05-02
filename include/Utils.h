#ifndef __UTILS_H__
#define __UTILS_H__

#include <unistd.h>

#define SLEEP_MS(ms) usleep(ms * 1000)

size_t readUntil(char *buf, char c, size_t max_len);
size_t readHTMLEnd(char *buf);

#endif  // __UTILS_H__
