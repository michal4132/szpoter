#ifndef __ZEROCONF_H__
#define __ZEROCONF_H__

#include <cstddef>
#include <cstdint>
#include <atomic>

class Zeroconf {
private:
    char *key = NULL;
    std::atomic<bool> run = false;
public:
    Zeroconf();
    ~Zeroconf();
    bool setKey(const char *_key);
    void stopZeroConfResponseHTTPServer();
    void startZeroConfResponseHTTPServer(uint16_t port);
};


#endif  // __ZEROCONF_H__
