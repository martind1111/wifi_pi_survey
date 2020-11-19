#ifndef _PACKET_HANDLER_H
#define _PACKET_HANDLER_H

#include "Packet.h"

class PacketHandler {
public:
    void radiotap_handler(const Packet* packet, u_char *user,
                          PacketSummary_t *packetInfo);

    void ieee802_11_handler(const Packet* packet, u_char *user,
                            PacketSummary_t *packetInfo);

    u_int16_t ethernet_handler(const Packet* packet, u_char *user);

    u_char *ip_handler(const Packet* packet, u_char *user);
};

#endif // _PACKET_HANDLER_H
