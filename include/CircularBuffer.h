#ifndef __CIRCULARBUFFER_H__
#define __CIRCULARBUFFER_H__

#include <vector>
#include <algorithm>
#include <mutex>
#include <cstring>

class CircularBuffer {
public:
    CircularBuffer(size_t dataCapacity);
    ~CircularBuffer();

    size_t size() const { return dataSize; }
    size_t capacity() const { return dataCapacity; }
    size_t write(const char *data, size_t bytes);
    size_t read(char *data, size_t bytes);
    void emptyBuffer();

private:
    std::mutex bufferMutex;
    size_t begIndex = 0;
    size_t endIndex = 0;
    size_t dataSize = 0;
    size_t dataCapacity = 0;
    char *buffer;
};

#endif  // __CIRCULARBUFFER_H__
