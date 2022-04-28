#include <cstdio>
#include "Zeroconf.h"
#include "Log.h"

int main(){
  LOG(debug, "Szpoter");
  Zeroconf zeroconf;
  zeroconf.startZeroConfResponseHTTPServer("key");
  return 0;
}
