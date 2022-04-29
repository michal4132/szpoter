#include <cstdio>
#include "Zeroconf.h"
#include "Log.h"
#include "Utils.h"

int main(){
  LOG(debug, "Szpoter");
  Zeroconf zeroconf;
  zeroconf.setKey("xd");
  zeroconf.startZeroConfResponseHTTPServer(2137);
  SLEEP_MS(1000);
  zeroconf.stopZeroConfResponseHTTPServer();
  return 0;
}
