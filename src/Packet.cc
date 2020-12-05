#include "Packet.h"

#include <pcap/pcap.h>

Packet::Packet(const struct pcap_pkthdr* pkthdr, const uint8_t* packet_data) :
    data(packet_data),
    length(pkthdr->len), capture_length(pkthdr->caplen),
    timestamp(pkthdr->ts) { }
