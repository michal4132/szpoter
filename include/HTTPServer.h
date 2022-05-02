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

// status mask
#define CONNECTION_GOT_REQUEST_TYPE 1   // parsed request type
#define CONNECTION_GOT_URL          2   // parsed url
#define CONNECTION_HEADERS_END      4   // received all headers
#define CONNECTION_START_RESPONSE   8   // unused
#define CONNECTION_HEADERS_SENT     16  // user sent headers
#define CONNECTION_RESERVED1        32  // unused
#define CONNECTION_RESERVED2        64  // unused
#define CONNECTION_CLOSE            128 // signal connection close

// http server config
#define BUFSIZE                     512
#define MAX_CONNECTIONS             10

// http server routes
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
    void *data;
    int16_t id;
    int context_length;
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

typedef void (*Response_cb)(Connection *con, void **arg);

typedef struct {
    const uint8_t method;
    const char *url;
    Response_cb cb;
    void **arg;
} Routes;

class HTTPServer {
private:
    std::thread server_thread;
    size_t recvData(struct pollfd fds, char *fp, size_t max_len);
    bool sendData(struct pollfd fds, char *fp, size_t data_len);
    int16_t fdsToConnectionNum(uint16_t fds);
    int16_t getEmpty();
    bool findRoute(Connection *con);
    void removeConnection(uint16_t i, uint16_t id);
    std::atomic<bool> running = true;
    char read_buffer[BUFSIZE];
    const Routes *routes = NULL;
    uint16_t port;
    uint16_t fds_size;
    struct pollfd fds[MAX_CONNECTIONS + 1];
    void loop();
public:
    Connection connections[MAX_CONNECTIONS];
    HTTPServer(uint16_t port, const Routes *_routes);
    ~HTTPServer();
    void stop();
};

int create_connection(uint16_t port);
int newcon(struct pollfd *fds, int i, int fds_size);
void connectionClose(Connection *con);

#endif  // __HTTPSERVER_H__
