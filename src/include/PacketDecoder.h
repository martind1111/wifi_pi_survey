#ifndef _PACKET_DECODER_H
#define _PACKET_DECODER_H

#define SUBTYPE_BITFIELD(fc) (fc >> 12)

class Packet;
struct WifiMetadata;
struct frame_control;

class PacketDecoder {
public:
    void Decode(const Packet* packet, void* user,
                WifiMetadata* wifiMetadata);

    static const char* get_ieee80211_type(const struct frame_control* control);
    static const char* get_ieee80211_subtype(const struct frame_control* control);
};

#endif // _PACKET_DECODER_H
