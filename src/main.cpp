#include <cstdio>
#include "Zeroconf.h"
#include "Log.h"
#include "Utils.h"
#include "HTTPServer.h"

// TODO:
//  - replace zeroconf server with http server

#define SPOTIFY_DISCOVER_PORT 2137

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

void getInfo_response(Connection *con) {
    con->send_response_code(200);
    con->send_response_header("Content-type", "application/json");
    con->response_end_header();
    con->write(getInfo_JSON, strlen(getInfo_JSON));
    con->close();
}

void post_response(Connection *con) {
    con->send_response_code(200);
    con->send_response_header("Content-type", "application/json");
    con->response_end_header();
    con->write(post_JSON, strlen(post_JSON));
    con->close();
}

int main() {
  LOG(debug, "Szpoter");

  Routes routes[] = {
    ROUTE_CGI(HTTP_GET, "/?action=getInfo", getInfo_response),
    ROUTE_CGI(HTTP_POST, "/", post_response),
    ROUTE_END()
  };

  HTTPServer http_server(SPOTIFY_DISCOVER_PORT, routes);
  while(true) {
    SLEEP_MS(1000);
  }

#if 0
  Zeroconf zeroconf;
  zeroconf.setKey("xd");
  zeroconf.startZeroConfResponseHTTPServer(SPOTIFY_DISCOVER_PORT);
  zeroconf.zeroConfDiscovery(SPOTIFY_DISCOVER_PORT);

  SLEEP_MS(10000);

  zeroconf.stopZeroConfResponseHTTPServer();
  zeroconf.stopZeroConfDiscovery();
#endif

  return 0;
}
