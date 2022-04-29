#ifndef __ZEROCONF_H__
#define __ZEROCONF_H__

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <thread>

class Zeroconf {
private:
    char *key = NULL;
    std::thread response_server_thread;
    std::thread avahi_thread;
    std::atomic<bool> run;
public:
    Zeroconf();
    ~Zeroconf();
    bool setKey(const char *_key);
    void stopZeroConfResponseHTTPServer();
    void startZeroConfResponseHTTPServer_thread(uint16_t port);
    void startZeroConfResponseHTTPServer(uint16_t port);
    void zeroConfDiscovery(uint16_t port);
    void stopZeroConfDiscovery();
};


#endif  // __ZEROCONF_H__
