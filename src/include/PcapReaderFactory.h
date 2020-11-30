#ifndef _PCAP_READER_FACTORY_H
#define _PCAP_READER_FACTORY_H

class ApplicationContext;
class PcapReader;

class PcapReaderFactory {
public:
    static PcapReader* MakePcapReader(ApplicationContext* context);
};

#endif // _PCAP_READER_FACTORY_H
