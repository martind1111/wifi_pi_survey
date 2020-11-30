#include "InterfaceReader.h"

#include "pcap/pcap.h"

#include "Application.h"

static const int PROMISC = 1;

static const int PACKET_BUFFER_TIMEOUT = 1000; // In milliseconds

pcap_t* InterfaceReader::Open(char* errbuf) {
    return pcap_open_live(this->GetContext()->dev, BUFSIZ, PROMISC,
                          PACKET_BUFFER_TIMEOUT, errbuf);
}
