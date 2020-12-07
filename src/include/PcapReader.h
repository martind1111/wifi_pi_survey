#ifndef _PCAP_READER_H
#define _PCAP_READER_H

#include "pcap/pcap.h"

#include "Worker.h"

class ApplicationContext;

void* PcapReaderRunner(void* context);

class PcapReader : public Worker {
public:
    PcapReader(ApplicationContext* context) : Worker(context) { }

    void Run() override;

    virtual pcap_t* Open(char* errbuf) = 0;
};

#endif // _PCAP_READER_H
