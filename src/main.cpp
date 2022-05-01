#include <cstdio>
#include "Zeroconf.h"
#include "Log.h"
#include "Utils.h"
#include "Crypto.h"

#define SPOTIFY_DISCOVER_PORT 2137

int main() {
  LOG(debug, "Szpoter");

  Zeroconf zeroconf;
  zeroconf.start(SPOTIFY_DISCOVER_PORT);

  Crypto crypto;
  crypto.DHInit();
  char *key = crypto.getKey();
  zeroconf.setKey(key);

  while(true) {
    SLEEP_MS(1000);
  }

  zeroconf.stop();

  return 0;
}
