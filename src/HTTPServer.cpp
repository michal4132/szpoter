#include "HTTPServer.h"
#include "Log.h"
#include "Utils.h"
#include <signal.h>

// TODO:
//  1. write CircularBuffer directly to socket

void notFoundPage(Connection *con) {
    con->send_response_code(404);
    con->send_response_header("Content-type", "text/html");
    con->response_end_header();
    con->write("404 File Not Found", strlen("404 File Not Found"));
    con->close();
}

HTTPServer::HTTPServer(uint16_t _port, const Routes *_routes) {
    routes = _routes;
    port = _port;
    server_thread = std::thread(&HTTPServer::loop, this);
}

int16_t HTTPServer::fdsToConnectionNum(uint16_t fds) {
    for (uint16_t i = 0; i < MAX_CONNECTIONS; ++i) {
        if (connections[i].id == fds) return i;
    }
    return -1;
}

int16_t HTTPServer::getEmpty() {
    for (uint16_t i = 0; i < MAX_CONNECTIONS; ++i) {
        if (connections[i].id == -1) return i;
    }
    return -1;
}

bool HTTPServer::findRoute(Connection *con) {
    uint16_t r = 0;
    while (routes[r].url != NULL) {
        if ( strlen(con->url) == strlen(routes[r].url) &&
            strncmp(routes[r].url, con->url, strlen(con->url)) == 0 &&
            con->method == routes[r].method) {
            routes[r].cb(con, routes[r].arg);
            return true;
        }
        r++;
    }
    return false;
}

void HTTPServer::loop() {
    int listener = create_connection(port);

    if (listener < 0)
        return;

    // prevent exit on broken pipe
    signal(SIGPIPE, SIG_IGN);

    fds_size = 1;
    fds[0].fd = listener;
    fds[0].events = POLLIN;

    LOG(debug, "HTTP Server started at port: %d", port);

    while (running) {
        poll(fds, fds_size, 1000);
        for (uint16_t i = 0; i < fds_size; i++) {
            if (fds[i].revents & POLLIN) {
                if (fds[i].fd == listener) {
                    // new connection
                    fds_size = newcon(fds, i, fds_size);
                    int16_t id = getEmpty();
                    if (id != -1) {
                        connections[id].state = 0;
                        connections[id].id = fds_size - 1;
                        fds[fds_size - 1].events = POLLIN;
                    } else {
                        LOG(error, "Max connections");
                        close(fds[fds_size - 1].fd);
                    }
                    break;
                } else {
                    Connection *con = &connections[fdsToConnectionNum(i)];
                    fds[i].events = POLLOUT;

                    // start parsing
                    size_t data_len;
                    if (con->state & CONNECTION_HEADERS_END) {
                        // only write data to connection buffer
                        data_len = recvData(fds[i], read_buffer, con->rx_buf.available());
                        con->rx_buf.write(read_buffer, data_len);
                        break;
                    } else {
                        data_len = recvData(fds[i], read_buffer, BUFSIZE);
                    }
                    uint32_t pos = 0;

                    // parse request type
                    if (!(con->state & CONNECTION_GOT_REQUEST_TYPE)) {
                        for (uint8_t l = 0; l < sizeof(http_methods)/sizeof(char *); ++l) {
                            uint16_t len = strlen(http_methods[l]);
                            if (strncmp(http_methods[l], read_buffer, len) == 0) {
                                pos += (len + 1);
                                con->method = l;
                                break;
                            }
                        }
                        con->state |= CONNECTION_GOT_REQUEST_TYPE;
                    }

                    // parse url
                    if (!(con->state & CONNECTION_GOT_URL)) {
                        size_t k = readUntil(read_buffer + pos, ' ', BUFSIZE - pos);
                        con->url = (char *) malloc(k + 1);
                        memcpy(con->url, read_buffer + pos, k);
                        con->url[k] = '\0';
                        con->state |= CONNECTION_GOT_URL;
                        readHTMLEnd(read_buffer+pos);
                        pos += readHTMLEnd(read_buffer+pos);
                    }

                    // read until data
                    if (!(con->state & CONNECTION_HEADERS_END)) {
                        while (true) {
                            size_t header_len = readHTMLEnd(read_buffer + pos);

                            if (strncmp(read_buffer + pos, "\r\n", 2) == 0) {
                                pos += header_len;
                                break;
                            } else if (strncmp(read_buffer + pos, "Content-Length", 14) == 0) {
                                con->context_length = atoi(read_buffer + pos + 16);
                            }

                            pos += header_len;
                        }
                        con->rx_buf.write(read_buffer + pos, data_len - pos);
                        con->state |= CONNECTION_HEADERS_END;
                        con->state |= CONNECTION_START_RESPONSE;
                    }
                }
            }
            if (fds[i].revents & POLLOUT){
                fds[i].events |= POLLIN;

                int16_t id = fdsToConnectionNum(i);
                Connection *con = &connections[id];
                // send http response
                if (con->state & CONNECTION_GOT_URL) {
                    if (!(con->state & CONNECTION_HEADERS_SENT)) {
                        LOG(debug, "%s Request %s", http_methods[con->method], con->url);
                    }

                    bool isRoute = findRoute(con);

                    // 404 not found
                    if (!isRoute) notFoundPage(con);
                }

                // TODO 1.
                size_t to_write = con->tx_buf.size();
                char *tmp = (char *) malloc(to_write);
                con->tx_buf.read(tmp, to_write);
                if (!sendData(fds[i], tmp, to_write)) {
                    con->close();
                }
                free(tmp);

                if (con->state & CONNECTION_CLOSE) {
                    con->clear();
                    close(fds[i].fd);

                    removeConnection(i, id);
                }
            }
        }
    }
}

void HTTPServer::removeConnection(uint16_t i, uint16_t id) {
    uint16_t j;
    for (j = i; j < fds_size - 1; ++j) {
        fds[j] = fds[j + 1];
    }
    fds_size--;

    for (j = id; j < MAX_CONNECTIONS - id; ++j) {
        if (connections[j].id > -1) {
            connections[j].id--;
        }
    }
}

void HTTPServer::stop() {
    running = false;
}

HTTPServer::~HTTPServer() {
    server_thread.join();
}

int create_connection(uint16_t port) {
    struct addrinfo hints, *p, *ai;
    int rv;
    int yes = 1;
    int listener;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_str[6];
    sprintf(port_str, "%d", port);

    if ((rv = getaddrinfo(NULL, port_str, &hints, &ai)) != 0) {
        LOG(error, "server: %s", gai_strerror(rv));
    }

    for (p = ai; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0)
            continue;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener);
            continue;
        }
        break;
    }

    if (p == NULL) {
        LOG(error, "server: can't bind");
        return -1;
    }

    freeaddrinfo(ai);
    if (listen(listener, MAX_CONNECTIONS) == -1) {
        LOG(error, "server: listen error");
        return -1;
    }
    return listener;
}

int newcon(struct pollfd *fds, int i, int fds_size) {
    struct sockaddr_storage remoteaddr;
    socklen_t addrlen = 0;
    fds_size++;
    fds[fds_size - 1].fd = accept(fds[i].fd,
                                  (struct sockaddr *)&remoteaddr,
                                  &addrlen);
    if (fds[fds_size-1].fd == -1) {
        LOG(error, "server, accept");
    } else {
        if (fcntl(fds[fds_size -1].fd, F_SETFL, O_NONBLOCK) == -1) {
            LOG(error, "server, fcntl");
        }
    }
    return fds_size;
}

size_t HTTPServer::recvData(struct pollfd fds, char *fp, size_t max_len) {
    int len = 0;
    while (len < max_len) {
        int curr_len = recv(fds.fd, fp + len, max_len - len, 0);
        if (curr_len > 0) {
            len += curr_len;
        } else if (curr_len == 0) {
            break;
        } else if (curr_len == -1 && errno == EAGAIN) {
            break;
        } else {
            LOG(error, "errno %d, reading: %d", errno, curr_len);
            break;
        }
    }
    return len;
}

bool HTTPServer::sendData(struct pollfd fds, char *fp, size_t data_len) {
    int pos = 0;
    while (pos < data_len) {
        int curr_len = send(fds.fd, fp + pos, data_len - pos, 0);
        if (curr_len > 0) {
            pos += curr_len;
        } else if (curr_len == 0) {
            break;
        } else if (curr_len == -1 && errno == EAGAIN) {
            return false;
            break;
        } else {
            LOG(error, "error writting %d %d", curr_len, errno);
            return false;
        }
    }
    return true;
}

Connection::Connection() {
    url = NULL;
    data = NULL;
    state = 0;
    id = -1;
    context_length = -1;
}

Connection::~Connection() {
    clear();
}

bool Connection::write(const char *buf, size_t len) {
    tx_buf.write(buf, len);
    return true;
}

size_t Connection::read(char *buf, size_t len) {
    return rx_buf.read(buf, len);
}

void Connection::send_response_code(uint16_t code) {
    const char *status_code;
    switch (code) {
        case 200:
            status_code = "OK";
            break;
        case 201:
            status_code = "Created";
            break;
        case 204:
            status_code = "No Content";
            break;
        case 206:
            status_code = "Partial Content";
            break;
        case 301:
            status_code = "Moved Permanently";
            break;
        case 400:
            status_code = "Bad Request";
            break;
        case 401:
            status_code = "Unauthorized";
            break;
        case 403:
            status_code = "Forbidden";
            break;
        case 404:
            status_code = "Not Found";
            break;
        case 500:
            status_code = "Internal Server Error";
            break;
    }
    char response_head[100];
    uint16_t len = snprintf(response_head, 100, "HTTP/1.1 %d %s\r\n", code, status_code);
    tx_buf.write(response_head, len);
}

void Connection::send_response_header(const char *name, const char *value) {
    char response_head[BUFSIZE];
    uint16_t len = snprintf(response_head, BUFSIZE, "%s: %s\r\n", name, value);
    tx_buf.write(response_head, len);
}

void Connection::response_end_header() {
    tx_buf.write("\r\n", 2);
    state |= CONNECTION_HEADERS_SENT;
}

void Connection::clear() {
    free(url);
    tx_buf.emptyBuffer();
    rx_buf.emptyBuffer();
    state = 0;
    id = -1;
}

void Connection::close() {
    state |= CONNECTION_CLOSE;
}
