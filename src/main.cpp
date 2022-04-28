#include <cstdio>
#include "Zeroconf.h"
#include "Log.h"

int main(){
  LOG(debug, "Szpoter");
  Zeroconf zeroconf;
  zeroconf.setKey("xd");
  zeroconf.startZeroConfResponseHTTPServer(2137);
  return 0;
}
