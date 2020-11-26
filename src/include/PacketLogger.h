#ifndef _PACKET_LOGGER_H
#define _PACKET_LOGGER_H

#include <stdint.h>

struct WifiMetadata;
class Packet;

class PacketLogger {
public:
    static void logRadiotap(void* user, WifiMetadata* wifiMetadata);
    static void log80211(const Packet* packet, void* user,
                         WifiMetadata* wifiMetadata);
    static uint16_t logEthernet(const Packet* packet, void* user);
    static void logIp(const Packet* packet, void* user);
};

#endif // _PACKET_LOGGER_H
