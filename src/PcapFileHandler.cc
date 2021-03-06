#include "PcapFileHandler.h"

#include <pcap/pcap.h>

bool PcapFileHandler::Open() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_offline(file_name.c_str(), errbuf);

    if (!pcap_handle) {
        return false;
    }

    return true;
}
