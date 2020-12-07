#ifndef _PCAP_FILE_HANDLER_H
#define _PCAP_FILE_HANDLER_H

#include <string>

#include "PcapHandler.h"

class PcapFileHandler : public PcapHandler {
public:
    PcapFileHandler(const std::string& fname) : PcapHandler(),
        file_name(fname) { }

    bool Open() override;

private:
    std::string file_name;
};

#endif // _PCAP_FILE_HANDLER_H
