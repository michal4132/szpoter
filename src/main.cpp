#include <cstdio>
#include "Zeroconf.h"
#include "Log.h"
#include "Utils.h"

#define SPOTIFY_DISCOVER_PORT 2137

int main() {
  LOG(debug, "Szpoter");

  Zeroconf zeroconf;
  zeroconf.start(SPOTIFY_DISCOVER_PORT);

  // test dynamic cgi
  char buf[20];
  int i = 0;
  while(true) {
    sprintf(buf, "%d", i++);
    zeroconf.setKey(buf);
    SLEEP_MS(1000);
  }

  zeroconf.stop();

  return 0;
}
