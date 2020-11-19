#include <stdio.h>
#include <string>
#include <map>
#include <set>
#include <list>
#include <bits/stl_pair.h>
#include <pcre.h>
#include <pthread.h>
#include <iostream>
#include <sstream>
#include <math.h>
#include "gps.h"
#include "libgpsmm.h"
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
#include "wiringPiI2C.h"

#include "wscan.h"
#include "pkt.h"
#include "wifi_types.h"
#include "radiotap.h"
#include "pdos80211.h"
#include "iwconfig.h"
extern "C" {
#include "create_pid_file.h"
#include "radiotap_iter.h"
#include "gps_utils.h"
}
#include "airodump-ng.h"
#include "networkDiscovery.h"
#include "heartbeat.h"
#include "database.h"
#include "manufacturer.h"

#include "PacketSummary.h"
#include "PacketHandler.h"
#include "PacketDecoder.h"

static char payload[MAX_PACKET_SIZE];

using namespace std;

namespace {
void updateSecurity(PacketSummary_t *packetInfo);
void dump_payload(char *payload, size_t payload_length);
}

/* Radiotap header Handler */
void
PacketHandler::radiotap_handler(const Packet* packet, uint8_t* user,
                                PacketSummary_t* packetInfo) {
  const uint8_t* packet_data = packet->GetData();
  WscanContext_t* context = (WscanContext_t*) user;
  size_t caplen = packet->GetCaptureLength(); // Length of portion present from
                                              // BPF
  size_t length = packet->GetLength(); // Length of this packet off the wire

  const struct ieee80211_radiotap_header* radiotap_hdr =
    (const struct ieee80211_radiotap_header*) packet_data;
  uint16_t radiotap_len = radiotap_hdr->it_len;

  if (caplen - radiotap_len < RT_VERSION_LEN + RT_LENGTH_LEN) {
    char errStr[256];

    sprintf(errStr, "Packet length is less than %d bytes: "
            "Invalid 802.11 radiotap header", RT_VERSION_LEN + RT_LENGTH_LEN);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return;
  }

  int antenna = 0, pwr = 0;
  packetInfo->channel = 0;
  packetInfo->rate = 0;
  packetInfo->txPower = 0;
  packetInfo->antenna = 0;
  packetInfo->dbSignal = 0;
  packetInfo->dbNoise = 0;
  packetInfo->dbSnr = 0;
  packetInfo->dbmSignal = 0;
  packetInfo->dbmNoise = 0;
  packetInfo->dbmSnr = 0;
  struct ieee80211_radiotap_iterator iterator;
  int ret = ieee80211_radiotap_iterator_init(
    &iterator,
    const_cast<ieee80211_radiotap_header*>(radiotap_hdr),
    radiotap_len);
  while (!ret) {
    ret = ieee80211_radiotap_iterator_next(&iterator);

    if (ret)
      continue;

    /* See if this argument is something we can use */

    switch (iterator.this_arg_index) {
    /*
     * You must take care when dereferencing iterator.this_arg
     * for multibyte types. The pointer is not aligned. Use
     * get_unaligned((type *)iterator.this_arg) to dereference
     * iterator.this_arg for type "type" safely on all architectures.
     */
    case IEEE80211_RADIOTAP_RATE:
      /* radiotap "rate" u8 is in
       * 500 kbps units, eg, 0x02=1Mbps
       */
      packetInfo->rate = (*iterator.this_arg) * 5; // In units of 100 kHz
      break;

    case IEEE80211_RADIOTAP_CHANNEL:
      packetInfo->channel = *((uint16_t *) iterator.this_arg);
      break;

    case IEEE80211_RADIOTAP_ANTENNA:
      /* radiotap uses 0 for 1st ant */
      packetInfo->antenna = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DBM_TX_POWER:
      packetInfo->txPower = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DBM_ANTNOISE:
      packetInfo->dbmNoise = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
      packetInfo->dbmSignal = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DB_ANTNOISE:
      packetInfo->dbNoise = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
      packetInfo->dbSignal = *iterator.this_arg;
      break;

    default:
      break;
    }
  }  /* while more rt headers */
}

/* IEEE 802.11 header Handler */
void
PacketHandler::ieee802_11_handler(const Packet* packet, uint8_t* user,
                                  PacketSummary_t* packetInfo) {
  const uint8_t* packet_data = packet->GetData();
  WscanContext_t* context = (WscanContext_t*) user;
  size_t caplen =
    packet->GetCaptureLength(); // Length of portion present from BPF
  size_t length = packet->GetLength(); // Length of this packet off the wire
  PacketDecoder packet_decoder;

  packetInfo->timestamp = packet->GetTimestamp();

  const struct ieee80211_radiotap_header* radiotap_hdr =
    (const struct ieee80211_radiotap_header*) packet_data;
  uint16_t radiotap_len = radiotap_hdr->it_len;

  if (caplen - radiotap_len < FC_LEN) {
    char errStr[256];

    sprintf(errStr, "Packet length is less than 2 bytes: "
            "Invalid 802.11 MAC header");

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return;
  }

  const struct mac_header* p =
    (const struct mac_header*) (packet_data + radiotap_len);
  const struct frame_control* control = (struct frame_control*) p->fc;

  packetInfo->security = 0;

  packetInfo->fromDs = control->from_ds;
  packetInfo->toDs = control->to_ds;

  packet_decoder.ParseAddresses(packet, packetInfo);

  updateSecurity(packetInfo);

  packetInfo->ssid[0] = 0;

  if (control->type == MGMT &&
      control->subtype == SUBTYPE_BITFIELD(ASSOCREQ_TYPE)) {
    packet_decoder.DecodeAssocReq((uint8_t*) p, caplen - radiotap_len,
                                  packetInfo);
  }
  else if (control->type == MGMT &&
           control->subtype == SUBTYPE_BITFIELD(BEACON_TYPE)) {
    packet_decoder.DecodeBeacon((uint8_t*) p, caplen - radiotap_len,
                                packetInfo);
  }
  else if (control->type == MGMT &&
           control->subtype == SUBTYPE_BITFIELD(PROBERESP_TYPE)) {
    packet_decoder.DecodeProbeResp((uint8_t*) p, caplen - radiotap_len,
                                   packetInfo);
  }
}

/* Ethernet Handler */
uint16_t
PacketHandler::ethernet_handler(const Packet* packet, uint8_t *user) {
  const uint8_t* packet_data = packet->GetData();
  WscanContext_t* context = (WscanContext_t*) user;
  size_t caplen =
    packet->GetCaptureLength(); // Length of portion present from BPF
  size_t length = packet->GetLength(); // Length of this packet off the wire
  const struct ether_header* eptr; // net/ethernet.h
  uint16_t ether_type; // The type of packet (we return this)
  eptr = (const struct ether_header*) packet_data;
  ether_type = ntohs(eptr->ether_type);

  if (caplen < 14) {
    char errStr[80];
    sprintf(errStr, "Packet length (%d) is less than header length", caplen);
    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

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

/* IP Handler */
uint8_t *
PacketHandler::ip_handler(const Packet* packet, uint8_t* user) {
  const uint8_t* packet_data = packet->GetData();
  WscanContext_t* context = (WscanContext_t *) user;
  const struct nread_ip* ip; // Packet structure
  const struct tcphdr* tcp; // TCP structure
  size_t length = packet->GetLength();  // Packet header length
  u_int hlen, off, version; // Offset, version
  int len; // Length holder

  ip = (const struct nread_ip*) (packet_data + sizeof(struct ether_header));
  length -= sizeof(struct ether_header);
  tcp = (const struct tcphdr*)
    (packet_data + sizeof(struct ether_header) + sizeof(struct nread_ip));

  hlen    = IP_HL(ip);         /* Get header length */
  len     = ntohs(ip->ip_len); /* Get packet length */
  version = IP_V(ip);          /* Get IP version    */

  if (hlen < 5 ) {
    char errStr[80];
    sprintf(errStr, "Alert: Bad header length %d", hlen);
    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);
  }

  if (length < len) {
    char errStr[80];
    sprintf(errStr, "Alert: Truncated %d bytes missing.", len - length);
    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);
  }

  off = ntohs(ip->ip_off);

  if ((off & 0x1fff) == 0 ) { /* aka no 1's in first 13 bits */
    if (context->vflag > 3) {
      fprintf(context->out,"ip: ");
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

  return NULL;
}

namespace {
void
updateSecurity(PacketSummary_t* packetInfo) {
  packetInfo->security = 0;

  if (!packetInfo->bssidPresent) {
    return;
  }

  NetworkInfo_t networkInfo;
  string bssid = string(ether_ntoa(&packetInfo->bssid));

  if (getNetwork(bssid, networkInfo)) {
    packetInfo->security = networkInfo.security;
  }
}

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
