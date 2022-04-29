#include <cstdio>
#include "Zeroconf.h"
#include "Log.h"
#include "Utils.h"

int main(){
  LOG(debug, "Szpoter");
  Zeroconf zeroconf;
  zeroconf.setKey("xd");
  // TODO start in thread
  zeroconf.startZeroConfResponseHTTPServer(2137);
  // TODO start in thread
  zeroconf.zeroConfDiscovery(2137);
  SLEEP_MS(10000);
  zeroconf.stopZeroConfResponseHTTPServer();
  zeroconf.stopZeroConfDiscovery();
  return 0;
}
