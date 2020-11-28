#ifndef _HARDWARE_HELPER_H
#define _HARDWARE_HELPER_H

struct ether_addr;

class HardwareHelper {
public:
static const char* GetManufacturer(struct ether_addr* addr);
};

#endif // _HARDWARE_HELPER_H
