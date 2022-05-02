#include "Utils.h"

size_t readUntil(char *buf, char c, size_t max_len) {
    size_t k = 0;
    while (*(buf + k) != c) {
        if (k < max_len) {
            k += 1;
        } else {
            break;
        }
    }
    return k;
}

size_t readHTMLEnd(char *buf) {
    size_t i = 0;
    while (!(buf[i] == '\r' && buf[i+1] == '\n')) { i++; };
    return i + 2;
}
