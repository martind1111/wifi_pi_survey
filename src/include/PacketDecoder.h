#ifndef _PACKET_DECODER_H
#define _PACKET_DECODER_H

#define SUBTYPE_BITFIELD(fc) (fc >> 12)

class Packet;
struct PacketSummary_t;
struct frame_control;

class PacketDecoder {
public:
    void ParseAddresses(const Packet* packet,
                        PacketSummary_t* packetInfo);

    int DecodeAssocReq(const uint8_t *packet_data, size_t packetLen,
                       PacketSummary_t* packetInfo);
    int DecodeBeacon(const uint8_t* packet, size_t packetLen,
                     PacketSummary_t* packetInfo);
    int DecodeProbeResp(const uint8_t* packet, size_t packetLen,
                        PacketSummary_t *packetInfo);

    static const char* get_ieee80211_type(const struct frame_control* control);
    static const char* get_ieee80211_subtype(const struct frame_control* control);
};

#endif // _PACKET_DECODER_H
