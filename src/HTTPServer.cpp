#include "HTTPServer.h"
#include "Log.h"
#include "Utils.h"

// WIP async web server

HTTPServer::HTTPServer(uint16_t _port, const Routes *_routes) {
    routes = _routes;
    port = _port;
    server_thread = std::thread(&HTTPServer::loop, this);
}

void HTTPServer::loop() {
    int listener;
    int i, j, k;
    int fds_size = 0;

    struct pollfd fds[MAX_CONNECTIONS + 1];

    listener = create_connection(port);

    fds_size++;
    fds[0].fd = listener;
    fds[0].events = POLLIN;

    LOG(debug, "HTTP Server started at port: %d", port);

    while(running) {
        poll(fds, fds_size, 1000);
        for(i = 0; i < fds_size; i++) {
            if (fds[i].revents & POLLIN) {
                if (fds[i].fd == listener) {
                    // new connection
                    fds_size = newcon(fds, i, fds_size);
                    connections[i + 1].state = 0;
                    fds[fds_size - 1].events = POLLIN;
                    break;
                } else {
                    // start parsing
                    uint32_t pos = 0;
                    size_t data_len = recvData(fds[i], read_buffer, BUFSIZE);

                    // parse request type
                    if(!(connections[i].state & CONNECTION_GOT_REQUEST_TYPE)) {
                        for(uint8_t l = 0; l < sizeof(http_methods)/sizeof(char *); ++l) {
                            uint16_t len = strlen(http_methods[l]);
                            if(strncmp(http_methods[l], read_buffer, len) == 0) {
                                pos += (len + 1);
                                connections[i].method = l;
                                break;
                            }
                        }
                        connections[i].state += CONNECTION_GOT_REQUEST_TYPE;
                    }

                    // parse url
                    if(!(connections[i].state & CONNECTION_GOT_URL)) {
                        k = 0;
                        while(*(read_buffer + pos + k) != ' ') k += 1; // skip until space
                        connections[i].url = (char *) malloc(k + 1);
                        memcpy(connections[i].url, read_buffer + pos, k);
                        connections[i].url[k] = '\0';
                        connections[i].state += CONNECTION_GOT_URL;
                    }

                    // read until data
                    if(!(connections[i].state & CONNECTION_HEADERS_END)) {
                        while(true) {
                            if(pos + 4 > BUFSIZE) break; // no data

                            if( (*(read_buffer + pos    ) == '\r') &&
                                (*(read_buffer + pos + 1) == '\n') &&
                                (*(read_buffer + pos + 2) == '\r') &&
                                (*(read_buffer + pos + 3) == '\n') ) {
                                break; // data
                            }
                            pos += 1;
                        }
                        connections[i].rx_buf.write(read_buffer + pos + 4, BUFSIZE - pos - 4);
                        connections[i].state += CONNECTION_HEADERS_END;
                        connections[i].state += CONNECTION_START_RESPONSE;
                    } else {
                        connections[i].rx_buf.write(read_buffer + pos, BUFSIZE - pos);
                    }

                    fds[i].events = POLLOUT;
                }
            }
            if(fds[i].revents & POLLOUT){
                // send http response
                if(connections[i].state & CONNECTION_GOT_URL) {
                    LOG(debug, "%s Request %s", http_methods[connections[i].method], connections[i].url);

                    uint16_t r = 0;
                    bool isRoute = false;
                    while(routes[r].url != NULL) {
                        if( strlen(connections[i].url) == strlen(routes[r].url) &&
                            strncmp(routes[r].url, connections[i].url, strlen(connections[i].url)) == 0 &&
                            connections[i].method == routes[r].method) {
                            routes[r].cb(&connections[i], routes[r].arg);
                            isRoute = true;
                            break;
                        }
                        r++;
                    }

                    // not found
                    if(!isRoute) {
                        connections[i].send_response_code(404);
                        connections[i].send_response_header("Content-type", "text/html");
                        connections[i].response_end_header();
                        connections[i].write("404 File Not Found", strlen("404 File Not Found"));
                        connections[i].close();
                    }
                }

                size_t to_write = connections[i].tx_buf.size();
                char *tmp = (char *) malloc(to_write);
                connections[i].tx_buf.read(tmp, to_write);
                sendData(fds[i], tmp, to_write);
                connections[i].tx_buf.emptyBuffer();

                if(connections[i].state & CONNECTION_CLOSE) {
                    connections[i].clear();
                    close(fds[i].fd);

                    for(j = i; j < fds_size - 1; j++) {
                        fds[j] = fds[j+1];
                    }
                    fds_size--;
                }
            }
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
    }

    freeaddrinfo(ai);
    if (listen(listener, MAX_CONNECTIONS) == -1) {
        LOG(error, "server: listen");
    }
    return listener;
}

int newcon(struct pollfd *fds, int i, int fds_size) {
    struct sockaddr_storage remoteaddr;
    socklen_t addrlen;
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
    while(true) {
        int curr_len = recv(fds.fd, fp + len, max_len - len, 0);
        if(curr_len > 0) {
            len += curr_len;
        } else if(curr_len == 0) {
            break;
        } else if (curr_len == -1 && errno == EAGAIN) {
            break;
        } else {
            LOG(error, "error reading %d %d", curr_len, errno);
            break;
        }
    }
    return len;
}

void HTTPServer::sendData(struct pollfd fds, char *fp, size_t data_len) {
    int pos = 0;
    while(pos < data_len) {
        int curr_len = send(fds.fd, fp + pos, data_len - pos, 0);
        if(curr_len > 0) {
            pos += curr_len;
        } else if(curr_len == 0) {
            break;
        } else if (curr_len == -1 && errno == EAGAIN) {
            break;
        } else {
            LOG(error, "error writting %d %d", curr_len, errno);
            break;
        }
    }
}

Connection::Connection() {
    url = NULL;
    state = 0;
}

Connection::~Connection() {
    free(url);
    tx_buf.emptyBuffer();
    rx_buf.emptyBuffer();
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
    switch(code) {
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
}

void Connection::clear() {
    free(url);
    tx_buf.emptyBuffer();
    rx_buf.emptyBuffer();
    state = 0;
}

void Connection::close() {
    if(state & CONNECTION_CLOSE) {
        return;
    }
    state += CONNECTION_CLOSE;
}
