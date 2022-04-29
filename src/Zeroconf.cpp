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

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>

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
    run = true;
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
    if(key != NULL) {
        free(key);
        key = NULL;
    }
}

void Zeroconf::stopZeroConfResponseHTTPServer() {
    run = false;
    LOG(debug, "Stopping ZeroConfReponseServer");
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

    while(run) {
        connfd = accept(sockfd, (struct sockaddr*)NULL, NULL);

        read_len = read(connfd, input, SERVER_BUFFER_SIZE);

        if (read_len < 0) {
            LOG(error, "ERROR reading from socket");
            return;
        }

        if(strncmp(getInfo_request_match, input, strlen(getInfo_request_match)) == 0) {
            char *message = (char *) malloc(strlen(getInfo_response_start) + strlen(key) + strlen(getInfo_response_end));
            strcpy(message, getInfo_response_start);
            strcat(message, (char*)key);
            strcat(message, getInfo_response_end);

            if(write(connfd, message, strlen(message)) != strlen(message)) {
                LOG(error, "ERROR writting to socket");
            }
            free(message);
        } else if(strncmp(post_data_request_match, input, strlen(post_data_request_match)) == 0) {
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


// avahi shit

static AvahiEntryGroup *group = NULL;
AvahiSimplePoll *simple_poll = NULL;
static char *name = NULL;
static void create_services(AvahiClient *c);
uint16_t spotify_port;


static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata) {
    assert(g == group || group == NULL);
    group = g;

    /* Called whenever the entry group state changes */

    switch (state) {
        case AVAHI_ENTRY_GROUP_ESTABLISHED :
            /* The entry group has been established successfully */
            LOG(debug, "Service '%s' successfully established.", name);
            break;

        case AVAHI_ENTRY_GROUP_COLLISION : {
            char *n;

            /* A service name collision with a remote service
             * happened. Let's pick a new name */
            n = avahi_alternative_service_name(name);
            avahi_free(name);
            name = n;

            LOG(error, "Service name collision, renaming service to '%s'", name);

            /* And recreate the services */
            create_services(avahi_entry_group_get_client(g));
            break;
        }

        case AVAHI_ENTRY_GROUP_FAILURE :

            LOG(error, "Entry group failure: %s", avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));

            /* Some kind of failure happened while we were registering our services */
            avahi_simple_poll_quit(simple_poll);
            break;

        case AVAHI_ENTRY_GROUP_UNCOMMITED:
        case AVAHI_ENTRY_GROUP_REGISTERING:
            ;
    }
}

static void create_services(AvahiClient *c) {
    char *n, r[128];
    int ret;
    assert(c);

    /* If this is the first time we're called, let's create a new
     * entry group if necessary */

    if (!group)
        if (!(group = avahi_entry_group_new(c, entry_group_callback, NULL))) {
            LOG(error, "avahi_entry_group_new() failed: %s", avahi_strerror(avahi_client_errno(c)));
        }

    /* If the group is empty (either because it was just created, or
     * because it was reset previously, add our entries.  */

    if (avahi_entry_group_is_empty(group)) {
        LOG(debug, "Adding service '%s'", name);

        /* Create some random TXT data */
        snprintf(r, sizeof(r), "VERSION=1.0\nCPath=/\nStack=SP");

        /* We will now add two services and one subtype to the entry
         * group. The two services have the same name, but differ in
         * the service type (IPP vs. BSD LPR). Only services with the
         * same name should be put in the same entry group. */

        /* Add the service for IPP */
        if ((ret = avahi_entry_group_add_service(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, (AvahiPublishFlags) 0, name, "_spotify-connect._tcp", NULL, NULL, spotify_port, "VERSION=1.0", "CPath=/", "Stack=SP", NULL)) < 0) {

            LOG(error, "Failed to add _ipp._tcp service: %s", avahi_strerror(ret));
        }
        /* Tell the server to register the service */
        if ((ret = avahi_entry_group_commit(group)) < 0) {
            LOG(error, "Failed to commit entry group: %s", avahi_strerror(ret));
        }
    }

    return;
}

static void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata) {
    assert(c);

    /* Called whenever the client or server state changes */

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:

            /* The server has startup successfully and registered its host
             * name on the network, so it's time to create our services */
            create_services(c);
            break;

        case AVAHI_CLIENT_FAILURE:

            LOG(error, "Client failure: %s", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(simple_poll);

            break;

        case AVAHI_CLIENT_S_COLLISION:

            /* Let's drop our registered services. When the server is back
             * in AVAHI_SERVER_RUNNING state we will register them
             * again with the new host name. */

        case AVAHI_CLIENT_S_REGISTERING:

            /* The server records are now being established. This
             * might be caused by a host name change. We need to wait
             * for our own records to register until the host name is
             * properly esatblished. */

            if (group)
                avahi_entry_group_reset(group);

            break;

        case AVAHI_CLIENT_CONNECTING:
            ;
    }
}

void Zeroconf::stopZeroConfDiscovery() {
    avahi_simple_poll_quit(simple_poll);
    LOG(debug, "Stopping ZeroConfDiscovery");
}

void Zeroconf::zeroConfDiscovery(uint16_t port){
    AvahiClient *client = NULL;
    int error_r;
    spotify_port = port;

    /* Allocate main loop object */
    if (!(simple_poll = avahi_simple_poll_new())) {
        LOG(error, "Failed to create simple poll object.");
    }

    name = avahi_strdup("Szpoter");

    /* Allocate a new client */
    client = avahi_client_new(avahi_simple_poll_get(simple_poll), (AvahiClientFlags) 0, client_callback, NULL, &error_r);

    /* Check wether creating the client object succeeded */
    if (!client) {
        LOG(error, "Failed to create client: %s", avahi_strerror(error_r));
        return;
    }
    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);
    LOG(debug, "avahi stopped");
    avahi_simple_poll_free(simple_poll);
}
