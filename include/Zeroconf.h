#ifndef __ZEROCONF_H__
#define __ZEROCONF_H__

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <thread>
#include "HTTPServer.h"


class Zeroconf {
private:
    char *key = NULL;
    std::thread avahi_thread;
    std::atomic<bool> run = true;
    HTTPServer *http_server;
public:
    Zeroconf();
    ~Zeroconf();
    bool setKey(const char *_key);
    void stop();
    void start(uint16_t port);
    void zeroConfDiscovery(uint16_t port);
    void stopZeroConfDiscovery();
};


#endif  // __ZEROCONF_H__
