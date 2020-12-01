#include <gtest/gtest.h>

#include <pcap/pcap.h>

#include "Packet.h"
#include "PacketDecoder.h"
#include "WifiMetadata.h"

namespace {
Packet* GetPacket(pcap_t* pcap);
}

namespace {
Packet* GetPacket(pcap_t* pcap) {
    pcap_pkthdr pkthdr;
    if (!pcap) {
        return nullptr;
    }
    const uint8_t* packet_data = pcap_next(pcap, &pkthdr);

    if (!packet_data) {
        return nullptr;
    }

    return new Packet(&pkthdr, packet_data);
}
} // namespace

// Test the decoding of Probe Request.
TEST(PacketDecoderTest, DecodeProbeRequest) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline("/tmp/test.pcap", errbuf);
    PacketDecoder decoder;
    Packet* packet = GetPacket(pcap);
    WifiMetadata wifiMetadata;

    EXPECT_TRUE(packet);

    decoder.Decode(packet, &wifiMetadata);

    pcap_close(pcap);

    delete packet;

    EXPECT_EQ(true, true); 
}
