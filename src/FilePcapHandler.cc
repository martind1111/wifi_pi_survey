#include "FilePcapHandler.h"

#include <pcap/pcap.h>

bool FilePcapHandler::Open() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_offline(file_name.c_str(), errbuf);

    if (!pcap_handle) {
        return false;
    }

    return true;
}
