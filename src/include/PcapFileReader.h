#ifndef _PCAP_FILE_READER_H
#define _PCAP_FILE_READER_H

#include "pcap/pcap.h"

#include "PcapReader.h"

class ApplicationContext;

class PcapFileReader : public PcapReader {
public:
    PcapFileReader(ApplicationContext* context) : PcapReader(context) { }

    pcap_t* Open(char* errbuf) override;
};

#endif // _PCAP_FILE_READER_H
