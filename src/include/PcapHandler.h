#ifndef _PCAP_HANDLER_H
#define _PCAP_HANDLER_H

#include <optional>
#include <string>

#include "Packet.h"

struct pcap;

class PcapHandler {
public:
    PcapHandler() : pcap_handle(nullptr) { }

    virtual bool Open() = 0;

    std::optional<Packet> GetNextPacket();

    void Close();

private:
    PcapHandler(const PcapHandler&) = delete;
    PcapHandler& operator=(const PcapHandler&) = delete;

protected:
    pcap* pcap_handle;
};

#endif // _PCAP_HANDLER_H
