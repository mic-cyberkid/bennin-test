#include "beacon/Beacon.h"
#include <objbase.h>

int main() {
    CoInitialize(NULL);
    beacon::Beacon beacon;
    beacon.run();
    return 0;
}
