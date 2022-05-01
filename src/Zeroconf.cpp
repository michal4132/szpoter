#include "Zeroconf.h"
#include "Log.h"
#include "Utils.h"
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

static const char getInfo_JSON[] =
    "{\"status\": 101, "
    "\"statusString\": \"OK\", "
    "\"spotifyError\": 0, "
    "\"version\": \"0.0.1\", "
    "\"deviceID\": \"162137fd329622137a14901634264e6f332e2422\", "
    "\"tokenType\": \"default\", "
    "\"publicKey\": \"%s\", "
    "\"remoteName\": \"Szpoter\", "
    "\"activeUser\": \"\"}";

static const char post_JSON[] =
    "{\"status\": 101, \"spotifyError\": 0, \"statusString\": \"ERROR-OK\"}";

static void getInfo_response(Connection *con, void **key) {
    if(*key != NULL) {
        con->send_response_code(200);
        con->send_response_header("Content-type", "application/json");
        con->response_end_header();
        size_t response_len = strlen(getInfo_JSON) + strlen((char *) *key) - 2; // subtract 2 (%s format)
        char *response = (char *) malloc(response_len);
        sprintf(response, getInfo_JSON, (char *) *key);
        con->write(response, response_len);
        free(response);
    }
    con->close();
}

static void post_response(Connection *con, void **) {
    if (!(con->state & CONNECTION_HEADERS_SENT)) { // connection init
        con->send_response_code(200);
        con->send_response_header("Content-type", "application/json");
        con->response_end_header();
        con->write(post_JSON, strlen(post_JSON));

        if (con->data != NULL) free(con->data);
        con->data = (int *) malloc(sizeof(int));
        (*(int *)(con->data)) = 0;
    }

    if (con->rx_buf.size() > 0) {
        char buf[BUFSIZE];
        (*(int *)(con->data)) += con->rx_buf.read(buf, BUFSIZE);
        LOG(debug, "user data: %s, len: %d", buf, (*(int *)(con->data)));
    }

    if ((*(int *)(con->data)) >= con->context_length) {
        con->close();
        free(con->data);
        con->data = NULL;
    }
}

// reference
// static void image_response(Connection *con, void **) {
//     if (!(con->state & CONNECTION_HEADERS_SENT)) { // connection init
//         con->send_response_code(200);
//         con->send_response_header("Content-type", "image/png");
//         con->response_end_header();
//
//         if(con->data != NULL) free(con->data);
//         con->data = (int *) malloc(sizeof(int));
//         (*(int *)(con->data)) = 0;
//
//         return;
//     }
//
//     int img_left = sizeof(image404) - (*(int *)(con->data));
//     int to_write = con->tx_buf.capacity() - con->tx_buf.size();
//
//     if(img_left <= to_write) {
//         to_write = img_left;
//     }
//
//     con->write((char *)image404+(*(int *)(con->data)), to_write);
//     LOG(debug, "wrote: %d, left: %d", to_write, img_left);
//     (*(int *)(con->data)) += to_write;
//
//     if(img_left == 0) {
//         con->close();
//         free(con->data);
//         con->data = NULL;
//     }
// }

static void test_response(Connection *con, void **) {
    if (!(con->state & CONNECTION_HEADERS_SENT)) { // connection init
        con->send_response_code(200);
        con->send_response_header("Content-type", "application/json");
        con->response_end_header();

        if(con->data != NULL) free(con->data);
        con->data = (int *) malloc(sizeof(int));
        (*(int *)(con->data)) = 0;

        return;
    }

    if ((*(int *)(con->data)) <= 10) {
        char buf[BUFSIZE];
        snprintf(buf, BUFSIZE, "%d", (*(int *)(con->data)));
        con->write("xd\n", strlen("xd\n"));
        con->write(buf, strlen(buf));
        (*(int *)(con->data))++;
        SLEEP_MS(100);
    } else {
        LOG(debug, "close");
        con->close();
        free(con->data);
        con->data = NULL;
    }
}

Zeroconf::Zeroconf() {
}

bool Zeroconf::setKey(const char *_key) {
    size_t key_len = strlen(_key) + 1;
    key = (char *) realloc(key, key_len);
    memcpy(key, _key, key_len);
    key[key_len] = '\0';
    return true;
}

Zeroconf::~Zeroconf() {
    if(key != NULL) {
        free(key);
        key = NULL;
    }
    stop();
    delete http_server;
}

void Zeroconf::stop() {
    http_server->stop();
    stopZeroConfDiscovery();
}

void Zeroconf::start(uint16_t port) {
    static Routes routes[] = {
        ROUTE_CGI_ARG(HTTP_GET, "/?action=getInfo\0", getInfo_response, (void **)&key),
        ROUTE_CGI(HTTP_GET, "/test", test_response),
        ROUTE_CGI(HTTP_POST, "/", post_response),
        ROUTE_END()
    };

    http_server = new HTTPServer(port, routes);
    this->zeroConfDiscovery(port);
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
    LOG(debug, "Stopping ZeroConfDiscovery");
    avahi_simple_poll_quit(simple_poll);
    avahi_thread.join();
    LOG(debug, "ZeroConfDiscovery stopped");
}

void avahi_loop_thread() {
    avahi_simple_poll_loop(simple_poll);
    avahi_simple_poll_free(simple_poll);
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
    avahi_thread = std::thread(avahi_loop_thread);
}
