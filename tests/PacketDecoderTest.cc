#include <gtest/gtest.h>

#include <pcap/pcap.h>

#include <list>

#include "airodump-ng.h"
#include "Packet.h"
#include "PacketDecoder.h"
#include "WifiMetadata.h"
#include "TestHelper.h"
#include "PcapFileHandler.h"

using namespace std;

// Test the decoding of Beacon frame.
TEST(PacketDecoderTest, DecodeBeacon) {
    string input_pcap = TestHelper::ResolvePath("tests/data/beacon.pcap");
    PacketDecoder decoder;
    WifiMetadata wifiMetadata;
    PcapFileHandler pcap_handler(input_pcap);

    pcap_handler.Open();

    optional<Packet> packet = pcap_handler.GetNextPacket(); 

    EXPECT_TRUE(packet);

    decoder.Decode(&packet.value(), &wifiMetadata);

    // Check radiotap header and radio information.
    EXPECT_EQ(static_cast<uint16_t>(wifiMetadata.channel), 0x6c09);
    EXPECT_EQ(wifiMetadata.rate, 10);
    EXPECT_EQ(wifiMetadata.antenna, 1);
    EXPECT_EQ(wifiMetadata.txPower, 0);
    EXPECT_EQ(wifiMetadata.dbNoise, 0);
    EXPECT_EQ(wifiMetadata.dbSignal, 0);
    EXPECT_EQ(wifiMetadata.dbSnr, 0);
    EXPECT_EQ(wifiMetadata.dbmNoise, 0);
    EXPECT_EQ(static_cast<uint8_t>(wifiMetadata.dbmSignal), 0xeb);
    EXPECT_EQ(wifiMetadata.dbmSnr, 0);

    EXPECT_TRUE(wifiMetadata.bssidPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.bssid), "28:c6:8e:8a:70:18");

    EXPECT_FALSE(wifiMetadata.raPresent);

    EXPECT_TRUE(wifiMetadata.destAddrPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.destAddr), "ff:ff:ff:ff:ff:ff");

    EXPECT_FALSE(wifiMetadata.taPresent);

    EXPECT_TRUE(wifiMetadata.srcAddrPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.srcAddr), "28:c6:8e:8a:70:18");

    EXPECT_EQ(wifiMetadata.fromDs, 0);
    EXPECT_EQ(wifiMetadata.toDs, 0);

    EXPECT_STREQ(wifiMetadata.ssid, "Createurs"); 

    EXPECT_EQ(wifiMetadata.security, STD_WPA2 | ENC_CCMP | AUTH_PSK); 

    packet = pcap_handler.GetNextPacket(); 

    EXPECT_FALSE(packet);

    pcap_handler.Close();
}

// Test the decoding of IEEE 802.11 Probe Request.
TEST(PacketDecoderTest, DecodeProbeRequest) {
    string input_pcap =
        TestHelper::ResolvePath("tests/data/probe_request.pcap");
    PacketDecoder decoder;
    WifiMetadata wifiMetadata;
    PcapFileHandler pcap_handler(input_pcap);

    pcap_handler.Open();

    optional<Packet> packet = pcap_handler.GetNextPacket(); 

    EXPECT_TRUE(packet);

    decoder.Decode(&packet.value(), &wifiMetadata);

    // Check radiotap header and radio information.
    EXPECT_EQ(static_cast<uint16_t>(wifiMetadata.channel), 0x6c09);
    EXPECT_EQ(wifiMetadata.rate, 0);
    EXPECT_EQ(wifiMetadata.antenna, 1);
    EXPECT_EQ(wifiMetadata.txPower, 0);
    EXPECT_EQ(wifiMetadata.dbNoise, 0);
    EXPECT_EQ(wifiMetadata.dbSignal, 0);
    EXPECT_EQ(wifiMetadata.dbSnr, 0);
    EXPECT_EQ(wifiMetadata.dbmNoise, 0);
    EXPECT_EQ(static_cast<uint8_t>(wifiMetadata.dbmSignal), 0xc1);
    EXPECT_EQ(wifiMetadata.dbmSnr, 0);

    EXPECT_TRUE(wifiMetadata.bssidPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.bssid), "ff:ff:ff:ff:ff:ff");

    EXPECT_FALSE(wifiMetadata.raPresent);

    EXPECT_TRUE(wifiMetadata.destAddrPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.destAddr), "ff:ff:ff:ff:ff:ff");

    EXPECT_FALSE(wifiMetadata.taPresent);

    EXPECT_TRUE(wifiMetadata.srcAddrPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.srcAddr), "94:9f:3e:8d:15:3b");

    EXPECT_EQ(wifiMetadata.fromDs, 0);
    EXPECT_EQ(wifiMetadata.toDs, 0);

    EXPECT_STREQ(wifiMetadata.ssid, ""); 

    packet = pcap_handler.GetNextPacket(); 

    EXPECT_FALSE(packet);

    pcap_handler.Close();
}

// Test the decoding of IEEE 802.11 Probe Response.
TEST(PacketDecoderTest, DecodeProbeResponse) {
    string input_pcap =
        TestHelper::ResolvePath("tests/data/probe_response.pcap");
    PacketDecoder decoder;
    WifiMetadata wifiMetadata;
    PcapFileHandler pcap_handler(input_pcap);

    pcap_handler.Open();

    optional<Packet> packet = pcap_handler.GetNextPacket(); 

    EXPECT_TRUE(packet);

    decoder.Decode(&packet.value(), &wifiMetadata);

    // Check radiotap header and radio information.
    EXPECT_EQ(static_cast<uint16_t>(wifiMetadata.channel), 0x7109);
    EXPECT_EQ(wifiMetadata.rate, 10);
    EXPECT_EQ(wifiMetadata.antenna, 1);
    EXPECT_EQ(wifiMetadata.txPower, 0);
    EXPECT_EQ(wifiMetadata.dbNoise, 0);
    EXPECT_EQ(wifiMetadata.dbSignal, 0);
    EXPECT_EQ(wifiMetadata.dbSnr, 0);
    EXPECT_EQ(wifiMetadata.dbmNoise, 0);
    EXPECT_EQ(static_cast<uint8_t>(wifiMetadata.dbmSignal), 0xa7);
    EXPECT_EQ(wifiMetadata.dbmSnr, 0);

    EXPECT_TRUE(wifiMetadata.bssidPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.bssid), "0:cb:51:fd:c2:e6");

    EXPECT_FALSE(wifiMetadata.raPresent);

    EXPECT_TRUE(wifiMetadata.destAddrPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.destAddr), "76:b5:83:c:bd:44");

    EXPECT_FALSE(wifiMetadata.taPresent);

    EXPECT_TRUE(wifiMetadata.srcAddrPresent);
    EXPECT_STREQ(ether_ntoa(&wifiMetadata.srcAddr), "0:cb:51:fd:c2:e6");

    EXPECT_EQ(wifiMetadata.fromDs, 0);
    EXPECT_EQ(wifiMetadata.toDs, 0);

    EXPECT_STREQ(wifiMetadata.ssid, "BELL916"); 

    packet = pcap_handler.GetNextPacket(); 

    EXPECT_FALSE(packet);

    pcap_handler.Close();
}
