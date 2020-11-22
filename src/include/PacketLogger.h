#ifndef _PACKET_LOGGER_H
#define _PACKET_LOGGER_H

struct WifiMetadata;

class PacketLogger {
public:
    static void logRadiotap(uint8_t* user, WifiMetadata* wifiMetadata);
    static void log80211(const Packet* packet, uint8_t* user,
                         WifiMetadata* wifiMetadata);
    static uint16_t logEthernet(const Packet* packet, uint8_t* user);
    static void logIp(const Packet* packet, uint8_t* user);
};

#endif // _PACKET_LOGGER_H
