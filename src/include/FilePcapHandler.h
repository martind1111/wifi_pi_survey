#ifndef _FILE_PCAP_HANDLER_H
#define _FILE_PCAP_HANDLER_H

#include <string>

#include "PcapHandler.h"

class FilePcapHandler : public PcapHandler {
public:
    FilePcapHandler(const std::string& fname) : PcapHandler(),
        file_name(fname) { }

    bool Open() override;

private:
    std::string file_name;
};

#endif // _FILE_PCAP_HANDLER_H
