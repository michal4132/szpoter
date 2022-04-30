#ifndef __HTTPSERVER_H__
#define __HTTPSERVER_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <atomic>
#include <thread>
#include "CircularBuffer.h"

#define CONNECTION_GOT_REQUEST_TYPE 1
#define CONNECTION_GOT_URL          2
#define CONNECTION_HEADERS_END      4
#define CONNECTION_START_RESPONSE   8
#define CONNECTION_RESERVED1        16
#define CONNECTION_RESERVED2        32
#define CONNECTION_RESERVED3        64
#define CONNECTION_CLOSE            128

#define BUFSIZE                     512
#define MAX_CONNECTIONS             10

#define ROUTE_CGI(method, url, function)  ROUTE_CGI_ARG(method, url, function, NULL)
#define ROUTE_CGI_ARG(method, url, function, arg)  {method, url, function, arg}
#define ROUTE_END() {0, NULL, NULL, NULL}


// HTTP Methods
#define HTTP_GET                    0
#define HTTP_POST                   1
#define HTTP_PUT                    2
#define HTTP_DELETE                 3
static const char *http_methods[] = {"GET", "POST", "PUT", "DELETE"};

class Connection {
// private:
public:
    uint8_t state;
    char *url;
    uint8_t method;
    CircularBuffer tx_buf = CircularBuffer(BUFSIZE);
    CircularBuffer rx_buf = CircularBuffer(BUFSIZE);
    Connection();
    ~Connection();
    bool write(const char *buf, size_t len);
    size_t read(char *buf, size_t len);
    void send_response_code(uint16_t code);
    void send_response_header(const char *name, const char *value);
    void response_end_header();
    void clear();
    void close();
};

typedef void (*Response_cb)(Connection *con, void *arg);

typedef struct {
    const uint8_t method;
    const char *url;
    Response_cb cb;
    void *arg;
} Routes;

class HTTPServer {
private:
    std::thread server_thread;
    size_t recvData(struct pollfd fds, char *fp, size_t max_len);
    void sendData(struct pollfd fds, char *fp, size_t data_len);
    std::atomic<bool> running = true;
    char read_buffer[BUFSIZE];
    Routes *routes = NULL;
    uint16_t port;
    void loop();
public:
    Connection connections[MAX_CONNECTIONS + 1];
    HTTPServer(uint16_t port, const Routes *_routes);
    ~HTTPServer();
    void stop();
};

int create_connection(uint16_t port);
int newcon(struct pollfd *fds, int i, int fds_size);
void connectionClose(Connection *con);

#endif  // __HTTPSERVER_H__
