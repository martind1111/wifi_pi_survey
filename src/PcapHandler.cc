#include "FilePcapHandler.h"

#include <pcap/pcap.h>

#include "Packet.h"

using namespace std;

optional<Packet> PcapHandler::GetNextPacket() {
    pcap_pkthdr pkthdr;

    if (!pcap_handle) {
        return nullopt;
    }

    const uint8_t* packet_data = pcap_next(pcap_handle, &pkthdr);

    if (!packet_data) {
        return nullopt;
    }

    return Packet(&pkthdr, packet_data);
}

void PcapHandler::Close() {
    pcap_close(pcap_handle);
}

