#ifndef _INTERFACE_READER_H
#define _INTERAFCE_READER_H

#include <pcap/pcap.h>

#include "PcapReader.h"

class ApplicationContext;

class InterfaceReader : public PcapReader {
public:
    InterfaceReader(ApplicationContext* context) : PcapReader(context) { }

    pcap_t* Open(char* errbuf) override;
};

#endif // _INTERFACE_READER_H
