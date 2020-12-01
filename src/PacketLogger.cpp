/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "PacketLogger.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/wireless.h>
#include <termios.h>
#include <netinet/ether.h>
#include <syslog.h>

#include <string>

#include <fmt/core.h>

#include "Application.h"
#include "pkt.h"
#include "WifiPacketTypes.h"
#include "radiotap.h"
#include "pdos80211.h"
extern "C" {
#include "radiotap_iter.h"
}
#include "airodump-ng.h"
#include "WifiMetadata.h"
#include "Packet.h"
#include "PacketDecoder.h"

static char payload[MAX_PACKET_SIZE];

using namespace std;

namespace {
void dump_payload(char* payload, size_t payload_length);
}

void
PacketLogger::logRadiotap(void* user, WifiMetadata* wifiMetadata) {
  ApplicationContext* context = reinterpret_cast<ApplicationContext*>(user);

  fprintf(context->out, "(radiotap) ");

  if (wifiMetadata->channel != 0)
    fprintf(context->out, "channel %d ", wifiMetadata->channel);

  if (wifiMetadata->rate != 0)
    fprintf(context->out, "rate %d ", wifiMetadata->rate);

  if (wifiMetadata->dbmSignal != 0)
    fprintf(context->out, "signal (dBm) %d ", wifiMetadata->dbmSignal);

  if (wifiMetadata->dbmNoise != 0)
    fprintf(context->out, "noise (dBm) %d ", wifiMetadata->dbmNoise);

  if (wifiMetadata->dbSignal != 0)
    fprintf(context->out, "signal (dB) %d ", wifiMetadata->dbSignal);

  if (wifiMetadata->dbNoise != 0)
    fprintf(context->out, "noise (dB) %d ", wifiMetadata->dbNoise);
}

void
PacketLogger::log80211(const Packet* packet, void* user,
                       WifiMetadata* wifiMetadata) {
  ApplicationContext* context = reinterpret_cast<ApplicationContext*>(user);
  const uint8_t* packet_data = packet->GetData();
  const struct ieee80211_radiotap_header* radiotap_hdr =
    (const struct ieee80211_radiotap_header*) packet_data;
  uint16_t radiotap_len = radiotap_hdr->it_len;

  if (packet->GetCaptureLength() - radiotap_len < FC_LEN) {
    return;
  }

  const struct mac_header* p =
    (const struct mac_header*) (packet_data + radiotap_len);
  const struct frame_control* control = (struct frame_control*) p->fc;

  fprintf(context->out, "(ieee802.11) ");
  fprintf(context->out, "%s ", PacketDecoder::get_ieee80211_type(control));
  fprintf(context->out, "%s ", PacketDecoder::get_ieee80211_subtype(control));

#if 0
  fprintf(context->out, "SC [ %d, %d ] ", *((uint16_t *) p->sc) & 0xf,
          *((uint16_t *) p->sc) >> 4);
#endif

  if (wifiMetadata->fromDs)
    fprintf(context->out, "From DS ");

  if (wifiMetadata->toDs)
    fprintf(context->out, "To DS ");

  if (context->eflag) {
    fprintf(context->out, "eth: ");
    if (wifiMetadata->bssidPresent) {
      fprintf(context->out, "BSSID %s ",
              ether_ntoa((struct ether_addr *) &wifiMetadata->bssid));
    }

    if (wifiMetadata->srcAddrPresent) {
      fprintf(context->out, "SA %s ",
              ether_ntoa((struct ether_addr *) &wifiMetadata->srcAddr));
    }

    if (wifiMetadata->destAddrPresent) {
      fprintf(context->out, "DA %s ",
              ether_ntoa((struct ether_addr *) &wifiMetadata->destAddr));
    }

    if (wifiMetadata->raPresent) {
      fprintf(context->out, "RA %s ",
              ether_ntoa((struct ether_addr *) &wifiMetadata->ra));
    }

    if (wifiMetadata->taPresent) {
      fprintf(context->out, "TA %s ",
              ether_ntoa((struct ether_addr *) &wifiMetadata->ta));
    }
  }

  if (wifiMetadata->ssid[0] != '\0') {
    fprintf(context->out, "SSID %s ", wifiMetadata->ssid);
  }

  fprintf(context->out, "\n");
}

// Log Ethernet layer
uint16_t
PacketLogger::logEthernet(const Packet* packet, void* user) {
  const uint8_t* packet_data = packet->GetData();
  ApplicationContext* context = reinterpret_cast<ApplicationContext*>(user);
  size_t caplen =
    packet->GetCaptureLength(); // Length of portion present from BPF
  size_t length = packet->GetLength(); // Length of this packet off the wire
  const struct ether_header* eptr; // net/ethernet.h
  uint16_t ether_type; // The type of packet (we return this)
  eptr = reinterpret_cast<const struct ether_header*>(packet_data);
  ether_type = ntohs(eptr->ether_type);

  if (caplen < 14) {
    string errStr =
      fmt::format("Packet length ({}) is less than header length", caplen);
    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());

    return -1;
  }

  if (context->eflag) {
    fprintf(context->out,"eth: ");
    fprintf(context->out, "%s ",
            ether_ntoa((struct ether_addr *) eptr->ether_shost));
    fprintf(context->out, "%s ",
            ether_ntoa((struct ether_addr *) eptr->ether_dhost));

    /* Get type and use as the beginning of the message line */
    if (ether_type == ETHERTYPE_IP) {
      fprintf(context->out, "(ip)");
    } else  if (ether_type == ETHERTYPE_ARP) {
      fprintf(context->out, "(arp)");
    } else  if (eptr->ether_type == ETHERTYPE_REVARP) {
      fprintf(context->out, "(rarp)");
    } else {
      fprintf(context->out, "(0x%04x)", ether_type);
    }
  }

  return ether_type;
}

// Log IP layer.
void
PacketLogger::logIp(const Packet* packet, void* user) {
  const uint8_t* packet_data = packet->GetData();
  ApplicationContext* context = reinterpret_cast<ApplicationContext*>(user);
  const struct nread_ip* ip; // Packet structure
  const struct tcphdr* tcp; // TCP structure
  size_t length = packet->GetLength();  // Packet header length
  size_t hlen, off, version; // Offset, version
  int len; // Length holder

  ip = reinterpret_cast<const struct nread_ip*>
    (packet_data + sizeof(struct ether_header));
  length -= sizeof(struct ether_header);
  tcp = reinterpret_cast<const struct tcphdr*>
    (packet_data + sizeof(struct ether_header) + sizeof(struct nread_ip));

  hlen = IP_HL(ip); // Get header length
  len = ntohs(ip->ip_len); // Get packet length
  version = IP_V(ip); // Get IP version

  if (hlen < 5 ) {
    string errStr = fmt::format("Alert: Bad header length {}", hlen);
    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());
  }

  if (length < len) {
    string errStr = fmt::format("Alert: Truncated {} bytes missing.",
                                len - length);
    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr.c_str());
  }

  off = ntohs(ip->ip_off);

  if ((off & 0x1fff) == 0 ) { /* aka no 1's in first 13 bits */
    if (context->vflag > 3) {
      fprintf(context->out, "ip: ");
    }

    if (context->vflag > 0) {
      fprintf(context->out, "%s:%u->%s:%u ",
              inet_ntoa(ip->ip_src), tcp->source,
              inet_ntoa(ip->ip_dst), tcp->dest);
    }

    if (context->vflag > 1) {
      fprintf(context->out, "tos %u len %u off %u ttl %u prot %u cksum %u ",
              ip->ip_tos, len, off, ip->ip_ttl,
              ip->ip_p, ip->ip_sum);
    }

    if (context->vflag > 2) {
      fprintf(context->out, "seq %u ack %u win %u ",
              tcp->seq, tcp->ack_seq, tcp->window);
    }

    if (context->vflag > 3) {
      if (ip->ip_p == PROTO_TCP) {
        if (length > sizeof(struct nread_ip) + sizeof(struct tcphdr)) {
          // There is TCP/UDP payload
          size_t payload_length = length - (hlen * 4);
          payload_length -= sizeof(struct tcphdr);
          memcpy(payload, tcp + sizeof(struct tcphdr), payload_length);
          fprintf(context->out, "tcp ");
          dump_payload(payload, payload_length);
        }
      }
      if (ip->ip_p == PROTO_UDP) {
        if (length > sizeof(struct nread_ip) + UDP_HEADER_SIZE) {
          fprintf(context->out, "udp ");
          size_t payload_length = length - (hlen * 4);
          payload_length -= UDP_HEADER_SIZE;
          dump_payload(payload, payload_length);
        }
      }
    }

    if (context->vflag > 0) {
      fprintf(context->out, "\n");
    }
  }
}

namespace {
void
dump_payload(char* payload, size_t payload_length) {
  size_t i;
  for (i = 0; i < payload_length; i++) {
    char c = payload[i];
    if (c < 32 || c > 126)
      fputc('.', stdout);
    else
      fputc(c, stdout);
  }
}
} // namespace
