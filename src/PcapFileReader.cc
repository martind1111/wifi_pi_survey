#include "PcapFileReader.h"

#include "pcap/pcap.h"

#include "Application.h"

pcap_t* PcapFileReader::Open(char* errbuf) {
    return pcap_open_offline(this->GetContext()->fileName, errbuf);
}
