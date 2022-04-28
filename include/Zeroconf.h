#ifndef __ZEROCONF_H__
#define __ZEROCONF_H__

#include <cstddef>
#include <cstdint>

class Zeroconf {
private:
    char *key = NULL;
public:
    Zeroconf();
    ~Zeroconf();
    bool setKey(const char *_key);
    void startZeroConfResponseHTTPServer(uint16_t port);
};


#endif  // __ZEROCONF_H__
