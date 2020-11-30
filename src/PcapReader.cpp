#include "PcapReader.h"

#include <stdio.h>
#include <string>
#include <sys/ioctl.h>
#include <errno.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/wireless.h>
#include <termios.h>
#include <netinet/ether.h>
#include <syslog.h>

#include "Application.h"
#include "pkt.h"
#include "wifi_types.h"
#include "radiotap.h"
#include "pdos80211.h"
extern "C" {
#include "radiotap_iter.h"
}
#include "airodump-ng.h"
#include "NetworkDiscovery.h"
#include "HeartbeatMonitor.h"
#include "WifiMetadata.h"
#include "Packet.h"
#include "PacketDecoder.h"
#include "PacketLogger.h"
#include "PcapReaderFactory.h"

static const char* MODULE_NAME = "PcapReader";

static char errbuf[PCAP_ERRBUF_SIZE];

using namespace std;

namespace {
void pcap_callback(uint8_t *user, const struct pcap_pkthdr* pkthdr,
                   const uint8_t* packet);
}

void *
MonitorPcap(void* context) {
  ApplicationContext* appContext =
    reinterpret_cast<ApplicationContext*>(context);
  PcapReader* reader = PcapReaderFactory::MakePcapReader(appContext);

  if (reader) {
    reader->Run();

    delete reader;
  }

  return nullptr;
}

void 
PcapReader::Run() {
  if (!this->GetContext()->dev && !this->GetContext()->fileName) {
    // Find the name of a suitable network device.
    this->GetMutableContext()->dev = pcap_lookupdev(errbuf);
  }

  if (!this->GetContext()->dev && !this->GetContext()->fileName) {
    fprintf(stderr, "%s\n", errbuf);

    this->GetMutableContext()->GetApplication()->Shutdown();

    return;
  }

  if (this->GetContext()->fileName) {
    fprintf(this->GetContext()->out, "Reading packets from file name %s\n",
            this->GetContext()->fileName);
  }
  else {
    fprintf(this->GetContext()->out, "Monitoring device %s\n",
            this->GetContext()->dev);
  }

  pcap_t* descr = Open(errbuf);

  if (!descr) {
    if (this->GetContext()->fileName) {
      fprintf(this->GetContext()->out, "pcap_open_offline(): %s\n", errbuf);
    }
    else {
      fprintf(this->GetContext()->out, "pcap_open_live(): %s\n", errbuf);
    }

    this->GetMutableContext()->GetApplication()->Shutdown();
   
    return;
  }

  if (this->GetContext()->outPcap != NULL) {
    this->GetMutableContext()->dumper =
        pcap_dump_fopen(descr, this->GetContext()->outPcap);
  }

  this->GetMutableContext()->datalink = pcap_datalink(descr);

  bpf_u_int32 net;

  bpf_u_int32 mask;

  pcap_lookupnet(this->GetContext()->dev, &net, &mask, errbuf);

  struct in_addr addr;

  addr.s_addr = net;

  fprintf(this->GetContext()->out, "Monitoring IP %s on data link %d\n",
          inet_ntoa(addr), this->GetContext()->datalink);

  struct bpf_program filter;

  if (this->GetContext()->oper) {
    fprintf(this->GetContext()->out, "Setting filter %s\n",
            this->GetContext()->oper);
    if (pcap_compile(descr, &filter, this->GetContext()->oper, 0, mask) == -1) {
      this->GetContext()->GetApplication()->LogError(
        this->GetContext()->opmode, MODULE_NAME,
        "Error calling pcap_compile");
      pcap_perror(descr, this->GetContext()->dev);
      exit(1);
    }

    if (pcap_setfilter(descr, &filter))  {
      this->GetContext()->GetApplication()->LogError(
        this->GetContext()->opmode, MODULE_NAME, "Error setting filter");
      exit(1);
    }
  }

  this->GetMutableContext()->descr = descr;

  pcap_loop(descr, this->GetContext()->npkts, pcap_callback,
            (uint8_t *) this->GetMutableContext()); /* Loop pcap */

  if (this->GetContext()->dumper != nullptr) {
    pcap_dump_close(this->GetContext()->dumper);
  }

  this->GetMutableContext()->GetApplication()->Shutdown();
}

namespace{
/* Callback */
void
pcap_callback(uint8_t* user, const struct pcap_pkthdr* pkthdr,
              const uint8_t* packet_data) {
  PacketDecoder packet_decoder;
  Packet packet(pkthdr, packet_data);
  ApplicationContext* context = reinterpret_cast<ApplicationContext*>(user);
  WifiMetadata wifiMetadata;
  int i;

  context->ReportActivity(ACTIVITY_MONITOR_INTERFACE);

  if (context->dumper != NULL) {
    pcap_dump((uint8_t*) context->dumper, pkthdr, packet_data);
  }

  if (context->vflag > 3) {
    for (i = 0; i < pkthdr->len; i++) {
      fprintf(context->out, "%02x ", packet_data[i]);
      if (i % 16 == 15)
        fprintf(context->out, "\n");
    }

    if (i % 16 != 0) {
      fprintf(context->out, "\n");
    }
  }

  if (context != nullptr && context->datalink == DLT_IEEE802_11_RADIO) {
    packet_decoder.Decode(&packet, user, &wifiMetadata);
    PacketLogger::logRadiotap(user, &wifiMetadata);
    PacketLogger::log80211(&packet, user, &wifiMetadata);

    NetworkDiscovery* networkDiscovery = context->GetNetworkDiscovery();
    networkDiscovery->UpdateNetworkResources(&wifiMetadata);

    if (networkDiscovery->IsEndNetworkIterator(context->networkIterator) &&
        networkDiscovery->GetNetworkCount() > 0) {
      networkDiscovery->BeginNetworkIterator(context->networkIterator);
    }
  }

  uint16_t type = PacketLogger::logEthernet(&packet, user);

  if (type == ETHERTYPE_IP) {
    PacketLogger::logIp(&packet, user);
  } else if (type == ETHERTYPE_ARP) {
    if (context->eflag && context->vflag > 0) {
      fprintf(context->out, "\n");
    }
  } else if (type == ETHERTYPE_REVARP) {
    if (context->eflag && context->vflag > 0) {
      fprintf(context->out, "\n");
    }
  }
  else {
    if (context->eflag && context->vflag > 0) {
      fprintf(context->out, "\n");
    }
  }
}
} // namespace
