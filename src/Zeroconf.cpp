#include "Zeroconf.h"
#include "Log.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#define SERVER_BUFFER_SIZE 2000

static const char getInfo_response_start[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: Szpoter\r\n"
    "Content-type: application/json\r\n"
    "\r\n"
    "{\"status\": 101, "
    "\"statusString\": \"OK\", "
    "\"spotifyError\": 0, "
    "\"version\": \"0.0.1\", "
    "\"deviceID\": \"162137fd329622137a14901634264e6f332e2422\", "
    "\"tokenType\": \"default\", "
    "\"publicKey\": \"";

static const char getInfo_response_end[] =
    "\", \"remoteName\": \"Szpoter\", "
    "\"activeUser\": \"\"}";


static const char post_response[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: szpoter\r\n"
    "Content-type: application/json\r\n"
    "\r\n"
    "{\"status\": 101, \"spotifyError\": 0, \"statusString\": \"ERROR-OK\"}";

// user requested device info
static const char getInfo_request_match[] = "GET /?action=getInfo HTTP/1.1";
// user sent own data
static const char post_data_request_match[] = "POST /";

Zeroconf::Zeroconf() {

}

// int sendClientResponse(char http[2048]);

bool Zeroconf::setKey(const char *_key) {
    if(key == NULL) {
        size_t key_len = strlen(_key);
        key = (char *) malloc(key_len);
        memcpy(key, _key, key_len);
        return true;
    } else {
        return false;
    }
}

Zeroconf::~Zeroconf() {
    free(key);
    key = NULL;
}

void Zeroconf::startZeroConfResponseHTTPServer(uint16_t port) {
    if(key == NULL) {
        LOG(error, "No public key");
        return;
    }
    LOG(debug, "Started ZeroConfReponseServer");
    int sockfd, connfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    int option = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    if (sockfd < 0) {
        LOG(error, "ERROR opening socket");
        return;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        LOG(error, "ERROR on binding");
        return;
    }
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    char input[SERVER_BUFFER_SIZE];
    size_t read_len;

    bool run = true;
    while(run){
        connfd = accept(sockfd, (struct sockaddr*)NULL, NULL);

        read_len = read(connfd, input, SERVER_BUFFER_SIZE);

        if (read_len < 0) {
            LOG(error, "ERROR reading from socket");
            return;
        }

        if(strncmp(getInfo_request_match, input, strlen(getInfo_request_match)) == 0){
            char *message = (char *) malloc(strlen(getInfo_response_start) + strlen(key) + strlen(getInfo_response_end));
            strcpy(message, getInfo_response_start);
            strcat(message, (char*)key);
            strcat(message, getInfo_response_end);

            if(write(connfd, message, strlen(message)) != strlen(message)) {
                LOG(error, "ERROR writting to socket");
            }
            free(message);
        }else if(strncmp(post_data_request_match, input, strlen(post_data_request_match)) == 0){
            if(write(connfd, post_response, strlen(post_response)) != strlen(post_response)) {
                LOG(error, "ERROR writting to socket");
            }
            // handle user key
//             if(sendClientResponse(input) == 1){
//               run = 0;
//             }
        }
        close(connfd);
    }
    close(sockfd);
}
