#include "Zeroconf.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "Log.h"

Zeroconf::Zeroconf() {

}

// int sendClientResponse(char http[2048]);

void Zeroconf::startZeroConfResponseHTTPServer(const char *key) {
    LOG(debug, "Started ZeroConfReponseServer");
    int sockfd, connfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    int n;
    int option = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    if (sockfd < 0) {
        LOG(error, "ERROR opening socket");
        return;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    // TODO
    portno = 2137;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        LOG(error, "ERROR on binding");
        return;
    }
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    int run = 1;
    while(run){
        connfd = accept(sockfd, (struct sockaddr*)NULL, NULL);

        char input[2048]; // shit

        n = read(connfd, input, 2048);

        if (n < 0) {
            LOG(error, "ERROR reading from socket");
            return;
        }

        // user requested device info
        char match[] = "GET /?action=getInfo HTTP/1.1";
        if(strncmp(match, input, strlen(match)) == 0){

            char start[] = "HTTP/1.1 200 OK\r\nServer: Szpoter\r\nContent-type: application/json\r\n\r\n{\"status\": 101, \"statusString\": \"OK\", \"spotifyError\": 0, \"version\": \"2.0.0\", \"deviceID\": \"162137fd329622137a14901634264e6f332e2422\", \"tokenType\": \"default\", \"publicKey\": \"";
            char end[] = "\", \"remoteName\": \"Szpoter\", \"activeUser\": \"\"}";
            char *message = (char *) malloc(strlen(start) + strlen((char*)key) + strlen(end));
            strcpy(message, start);
            strcat(message, (char*)key);
            strcat(message, end);

            n = write(connfd, message, strlen(message));
            free(message);
        }

        // user sent own data
        char match2[] = "POST /";
        if(strncmp(match2, input, strlen(match2)) == 0){
            char post_response[] = "HTTP/1.1 200 OK\r\nServer: szpoter\r\nContent-type: application/json\r\n\r\n{\"status\": 101, \"spotifyError\": 0, \"statusString\": \"ERROR-OK\"}";
            n = write(connfd, post_response, strlen(post_response));
    //         if(sendClientResponse(input) == 1){
    //           run = 0;
    //         }
        }
        close(connfd);
    }
    close(sockfd);
}
