#ifndef __ZEROCONF_H__
#define __ZEROCONF_H__

class Zeroconf {
private:
    int test = 0;
public:
    Zeroconf();
    void startZeroConfResponseHTTPServer(const char *key);
};


#endif  // __ZEROCONF_H__
