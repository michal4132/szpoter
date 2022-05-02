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
        size_t response_len = strlen(getInfo_JSON) + strlen((const char *) *key) - 2; // subtract 2 (%s format)
        char *response = (char *) malloc(response_len);
        sprintf(response, getInfo_JSON, *key);
        con->write(response, response_len);
        free(response);
    }
    con->close();
}

typedef struct {
    size_t pos;
    char *read_data;
} POSTdata;

static void post_response(Connection *con, void **) {
    POSTdata *data = (POSTdata *) con->data;

    if (!(con->state & CONNECTION_HEADERS_SENT)) { // connection init
        con->send_response_code(200);
        con->send_response_header("Content-type", "application/json");
        con->response_end_header();
        con->write(post_JSON, strlen(post_JSON));

        free(con->data);
        con->data = (POSTdata *) malloc(sizeof(POSTdata));
        data = (POSTdata *) con->data;
        data->pos = 0;
        data->read_data = (char *) malloc(con->context_length);
    }

    if (con->rx_buf.size() > 0) { // read all data
        size_t read_len = con->rx_buf.read(data->read_data + data->pos, con->context_length - data->pos);
        data->pos += read_len;
    }

    if (data->pos >= con->context_length) { // parse data and close connection
        size_t pos = 0;
        while(true) {
            // TODO: reduce dynamic allocation, parse data in real time
            size_t arg_len = readUntil(data->read_data + pos, '=', con->context_length - pos);
            char *arg = (char *) malloc(arg_len + 1);
            memcpy(arg, data->read_data + pos, arg_len);
            arg[arg_len] = '\0';
            pos += arg_len + 1;

            size_t val_len = readUntil(data->read_data + pos, '&', con->context_length - pos);
            char *val = (char *) malloc(val_len + 1);
            memcpy(val, data->read_data + pos, val_len);
            val[val_len] = '\0';
            pos += val_len + 1;

            LOG(debug, "arg: %s, val: %s", arg, val);

            free(arg);
            free(val);

            if (pos >= con->context_length) {
                break;
            }
        }

        con->close();
        free(data->read_data);
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
//         free(con->data);
//         con->data = (int *) malloc(sizeof(int));
//         (*(int *)(con->data)) = 0;
//
//         return;
//     }
//
//     int img_left = sizeof(image404) - (*(int *)(con->data));
//     int to_write = con->tx_buf.capacity() - con->tx_buf.size();
//
//     if (img_left <= to_write) {
//         to_write = img_left;
//     }
//
//     con->write((char *)image404+(*(int *)(con->data)), to_write);
//     LOG(debug, "wrote: %d, left: %d", to_write, img_left);
//     (*(int *)(con->data)) += to_write;
//
//     if (img_left == 0) {
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

        free(con->data);
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
    free(key);
    key = NULL;
    stop();
    delete http_server;
}

void Zeroconf::stop() {
    http_server->stop();
    stopZeroConfDiscovery();
}

void Zeroconf::start(uint16_t port) {
    static Routes routes[] = {
        ROUTE_CGI_ARG(HTTP_GET, "/?action=getInfo", getInfo_response, (void **)&key),
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


    switch (state) {
        case AVAHI_ENTRY_GROUP_ESTABLISHED :
            LOG(debug, "Service '%s' successfully established.", name);
            break;

        case AVAHI_ENTRY_GROUP_COLLISION : {
            char *n;

            n = avahi_alternative_service_name(name);
            avahi_free(name);
            name = n;

            LOG(error, "Service name collision, renaming service to '%s'", name);
            create_services(avahi_entry_group_get_client(g));
            break;
        }
        case AVAHI_ENTRY_GROUP_FAILURE :
            LOG(error, "Entry group failure: %s", avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
            avahi_simple_poll_quit(simple_poll);
            break;
    }
}

static void create_services(AvahiClient *c) {
    int ret;
    assert(c);

    if (!group)
        if (!(group = avahi_entry_group_new(c, entry_group_callback, NULL))) {
            LOG(error, "avahi_entry_group_new() failed: %s", avahi_strerror(avahi_client_errno(c)));
        }

    if (avahi_entry_group_is_empty(group)) {
        LOG(debug, "Adding service '%s'", name);

        if ((ret = avahi_entry_group_add_service(group,
                    AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
                    (AvahiPublishFlags) 0, name,
                    "_spotify-connect._tcp",
                    NULL, NULL, spotify_port, "VERSION=1.0",
                    "CPath=/", "Stack=SP", NULL)) < 0) {
            LOG(error, "Failed to add _ipp._tcp service: %s", avahi_strerror(ret));
        }
        if ((ret = avahi_entry_group_commit(group)) < 0) {
            LOG(error, "Failed to commit entry group: %s", avahi_strerror(ret));
        }
    }

    return;
}

static void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata) {
    assert(c);

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            create_services(c);
            break;

        case AVAHI_CLIENT_FAILURE:
            LOG(error, "Client failure: %s", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(simple_poll);
            break;

        case AVAHI_CLIENT_S_REGISTERING:
            if (group)
                avahi_entry_group_reset(group);
            break;
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

    if (!(simple_poll = avahi_simple_poll_new())) {
        LOG(error, "Failed to create simple poll object.");
    }

    name = avahi_strdup("Szpoter");

    client = avahi_client_new(avahi_simple_poll_get(simple_poll), (AvahiClientFlags) 0, client_callback, NULL, &error_r);

    if (!client) {
        LOG(error, "Failed to create client: %s", avahi_strerror(error_r));
        return;
    }
    avahi_thread = std::thread(avahi_loop_thread);
}
