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
#include <algorithm>

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

#include "Packet.h"
#include "PacketSummary.h"
#include "PacketDecoder.h"

namespace {
void copy_ether_addr(struct ether_addr* destAddr,
                     const struct ether_addr* srcAddr);
}

void
PacketDecoder::ParseAddresses(const Packet* packet,
                              PacketSummary_t* packetInfo) {
  size_t caplen =
    packet->GetCaptureLength(); // Length of portion present from BPF
  size_t length = packet->GetLength(); // Length of this packet off the wire
  struct ieee80211_radiotap_header *radiotap_hdr =
    (struct ieee80211_radiotap_header*) packet->GetData();
  size_t radiotap_len = radiotap_hdr->it_len;

  const struct mac_header* p = (struct mac_header*) (packet + radiotap_len);
  const struct frame_control* control = (struct frame_control*) p->fc;

  // Extract MAC address
  packetInfo->bssidPresent = false;
  memset(&packetInfo->bssid, 0, ETH_ALEN);
  packetInfo->srcAddrPresent = false;
  memset(&packetInfo->srcAddr, 0, ETH_ALEN);
  packetInfo->destAddrPresent = false;
  memset(&packetInfo->destAddr, 0, ETH_ALEN);
  packetInfo->raPresent = false;
  memset(&packetInfo->ra, 0, ETH_ALEN);
  packetInfo->taPresent = false;
  memset(&packetInfo->ta, 0, ETH_ALEN);

  if (control->type == 0x01 &&
      control->subtype == SUBTYPE_BITFIELD(BLOCKACK_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->raPresent = true;
      copy_ether_addr(&packetInfo->ra, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      packetInfo->taPresent = true;
      copy_ether_addr(&packetInfo->ta, &p->addr2);
    }
  }
  else if (control->type == 0x01 &&
      control->subtype == SUBTYPE_BITFIELD(PS_POLL_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->bssidPresent = true;
      copy_ether_addr(&packetInfo->bssid, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      packetInfo->raPresent = true;
      copy_ether_addr(&packetInfo->ra, &p->addr2);
    }
  }
  else if (control->type == 0x01 &&
           control->subtype == SUBTYPE_BITFIELD(RTS_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->raPresent = true;
      copy_ether_addr(&packetInfo->ra, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      packetInfo->taPresent = true;
      copy_ether_addr(&packetInfo->ta, &p->addr2);
    }
  }
  else if (control->type == 0x01 &&
           control->subtype == SUBTYPE_BITFIELD(CTS_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->raPresent = true;
      copy_ether_addr(&packetInfo->ra, &p->addr1);
    }
  }
  else if (control->type == 0x01 &&
           control->subtype == SUBTYPE_BITFIELD(ACK_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->raPresent = true;
      copy_ether_addr(&packetInfo->ra, &p->addr1);
    }
  }
  else if (control->to_ds == 0 && control->from_ds == 0) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->destAddrPresent = true;
      copy_ether_addr(&packetInfo->destAddr, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      packetInfo->srcAddrPresent = true;
      copy_ether_addr(&packetInfo->srcAddr, &p->addr2);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 3 * sizeof(struct ether_addr)) {
      packetInfo->bssidPresent = true;
      copy_ether_addr(&packetInfo->bssid, &p->addr3);
    }
  }
  else if (control->to_ds == 0 && control->from_ds == 1) {
    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->destAddrPresent = true;
      copy_ether_addr(&packetInfo->destAddr, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      packetInfo->bssidPresent = true;
      copy_ether_addr(&packetInfo->bssid, &p->addr2);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 3 * sizeof(struct ether_addr)) {
      packetInfo->srcAddrPresent = true;
      copy_ether_addr(&packetInfo->srcAddr, &p->addr3);
    }
  }
  else if (control->to_ds == 1 && control->from_ds == 0) {
    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->bssidPresent = true;
      copy_ether_addr(&packetInfo->bssid, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      packetInfo->srcAddrPresent = true;
      copy_ether_addr(&packetInfo->srcAddr, &p->addr2);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 3 * sizeof(struct ether_addr)) {
      packetInfo->destAddrPresent = true;
      copy_ether_addr(&packetInfo->destAddr, &p->addr3);
    }
  }
  else if (control->to_ds == 1 && control->from_ds == 1) {
    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      packetInfo->raPresent = true;
      copy_ether_addr(&packetInfo->ra, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      packetInfo->taPresent = true;
      copy_ether_addr(&packetInfo->ta, &p->addr2);
    }
    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 3 * sizeof(struct ether_addr)) {
      packetInfo->destAddrPresent = true;
      copy_ether_addr(&packetInfo->destAddr, &p->addr3);
    }
  }
}

/**
 * Decode Association Request message.
 *
 * @return -1 if error, 0 otherwise.
 */
int
PacketDecoder::DecodeAssocReq(const uint8_t *packet_data, size_t packetLen,
                              PacketSummary_t* packetInfo) {
  const struct mgmt_hdr* mgmthdr;
  const struct mgmt_ie_hdr* ie;
  const uint8_t* body;
  int i;

  mgmthdr = (const struct mgmt_hdr*) packet_data;
  body = (const uint8_t*) packet_data + MGMT_HDR_LEN;

  if ((body + FIELD_CAP_LEN + FIELD_LI_LEN) > (packet_data + packetLen)) {
    return -1;
  }

  const uint8_t capab = *body;

  if (packetInfo->security & STD_WEP) {
    if (capab == 0x00) {
      packetInfo->security |= AUTH_OPN;
    }
    if (capab == 0x01) {
      packetInfo->security |= AUTH_PSK;
    }
  }

  body += FIELD_CAP_LEN;

  body += FIELD_LI_LEN;

  // Decode information elements.
  size_t ssid_len;
  while (body < (packet_data + packetLen)) {
    ie = (const struct mgmt_ie_hdr*) body;
    body += 2;
    if ((body + ie->len) > (packet_data + packetLen)) {
      return -1;
    }

    switch(ie->id) {
    case IE_SSID_ID:
      ssid_len = std::min(ie->len, static_cast<const uint8_t>(MAX_SSID_LEN));
      memcpy(packetInfo->ssid, body, ssid_len);
      packetInfo->ssid[ssid_len] = '\0';
      body += ie->len;
      break;
    default:
      body += ie->len;
      break;
    }
  }

  return 0;
}

int
PacketDecoder::DecodeProbeResp(const uint8_t* packet_data, size_t packetLen,
                               PacketSummary_t* packetInfo) {
  const struct mgmt_hdr* mgmthdr;
  const struct mgmt_ie_hdr* ie;
  const uint8_t* body;
  int i;

  mgmthdr = (const struct mgmt_hdr *) packet_data;
  body = (const uint8_t *) packet_data + MGMT_HDR_LEN;

  if ((body + FIELD_TS_LEN + FIELD_BI_LEN + FIELD_CAP_LEN) >
      (packet_data + packetLen)) {
    return -1;
  }

  body += FIELD_TS_LEN;

  body += FIELD_BI_LEN;

  const uint8_t capab = *body;

  if (capab >> 4) {
    packetInfo->security |= STD_WEP | ENC_WEP;
  }
  else {
    packetInfo->security |= STD_OPN;
  }

  body += FIELD_CAP_LEN;

  // Decode information elements.
  size_t ssid_len;
  while (body < (packet_data + packetLen)) {
    ie = (const struct mgmt_ie_hdr*) body;
    body += 2;
    if ((body + ie->len) > (packet_data + packetLen)) {
      return -1;
    }

    switch(ie->id) {
    case IE_SSID_ID:
      ssid_len = std::min(ie->len, static_cast<uint8_t>(MAX_SSID_LEN));
      memcpy(packetInfo->ssid, body, ssid_len);
      packetInfo->ssid[ssid_len] = '\0';
      if (ie->len >= MAX_SSID_LEN) {
        packetInfo->ssid[MAX_SSID_LEN] = '\0';
      }
      body += ie->len;
      break;
    default:
      body += ie->len;
      break;
    }
  }

  return 0;
}

int
PacketDecoder::DecodeBeacon(const uint8_t* packet_data, size_t packetLen,
                            PacketSummary_t* packetInfo) {
  const struct mgmt_hdr* mgmthdr;
  const struct mgmt_ie_hdr* ie;
  const uint8_t* body;
  int i;
  char tmp;

  mgmthdr = (const struct mgmt_hdr*) packet_data;
  body = (const uint8_t*) packet_data + MGMT_HDR_LEN;

  if ((body + FIELD_TS_LEN + FIELD_BI_LEN + FIELD_CAP_LEN) >
      (packet_data + packetLen)) {
    return -1;
  }

  body += FIELD_TS_LEN;

  body += FIELD_BI_LEN;

  const uint8_t capab = *body;

  if (capab >> 4) {
    packetInfo->security |= STD_WEP | ENC_WEP;
  }
  else {
    packetInfo->security |= STD_OPN;
  }

  body += FIELD_CAP_LEN;

  // Decode information elements.
  size_t ssid_len;
  while (body < (packet_data + packetLen)) {
    const uint8_t* p = body;
    ie = (const struct mgmt_ie_hdr*) body;
    body += 2;
    if ((body + ie->len) > (packet_data + packetLen)) {
      return -1;
    }

    int numuni;
    int numauth;
    int i;
    switch(ie->id) {
    case IE_SSID_ID:
      ssid_len = std::min(ie->len, static_cast<uint8_t>(MAX_SSID_LEN));
      memcpy(packetInfo->ssid, body, ssid_len);
      packetInfo->ssid[ssid_len] = '\0';
      body += ie->len;
      break;
    case 0x30:
    case 0xDD:
      if ((ie->id == 0xDD && ie->len > 22 &&
           memcmp(body, "\x00\x50\xF2\x01\x01\x00", ETH_ALEN) == 0) ||
          (ie->id  == 0x30)) {
        packetInfo->security &= ~(STD_WEP | ENC_WEP);

        if (ie->id == 0xDD) {
          // WPA defined in vendor specific tag -> WPA1 support
          packetInfo->security |= STD_WPA;

          numuni = p[12] + (p[13] << 8);
          numauth = p[14 + 4 * numuni] + (p[15 + 4 * numuni] << 8);

          p = p + 14; // Point at first unicast cipher
        }
        else if (ie->id == 0x30) {
          packetInfo->security |= STD_WPA2;

          numuni = p[8] + (p[9] << 8);
          numauth = p[10 + 4 * numuni] + (p[11 + 4 * numuni] << 8);

          p += 10;
        }

        for (i = 0; i < numuni; i++) {
          switch(p[i * 4 + 3]) {
          case 0x01:
            packetInfo->security |= ENC_WEP;
            break;
          case 0x02:
            packetInfo->security |= ENC_TKIP;
            break;
          case 0x03:
            packetInfo->security |= ENC_WRAP;
            break;
          case 0x04:
            packetInfo->security |= ENC_CCMP;
            break;
          case 0x05:
            packetInfo->security |= ENC_WEP104;
            break;
          default:
            break;
          }
        }

        p += 2 + 4 * numuni;

        for (i = 0; i < numauth; i++) {
          switch(p[i * 4 + 3]) {
          case 0x01:
            packetInfo->security |= AUTH_MGT;
            break;
          case 0x02:
            packetInfo->security |= AUTH_PSK;
            break;
          default:
            break;
          }
        }

        p += 2 + 4 * numauth;
        if (ie->id == 0x30) {
          p += 2;
        }
      }
      body += ie->len;
      break;
    default:
      body += ie->len;
      break;
    }
  }

  return 0;
}


namespace {
void copy_ether_addr(struct ether_addr *destAddr,
                     const struct ether_addr *srcAddr) {
  int i;

  for (i = 0; i < ETH_ALEN; i++) {
    destAddr->ether_addr_octet[i] = srcAddr->ether_addr_octet[i];
  }
}
} // namespace

const char *
get_ieee80211_type(const struct frame_control* control) {
  switch (control->type) {
  case MGMT:
    return "Management";
  case 1:
    return "Control";
  case 2:
    return "Data";
  case 3:
    return "Reserved";
  default:
    break;
  }

  return "";
}

const char *
get_ieee80211_subtype(const struct frame_control* control) {
  if (control->type == MGMT) {
    switch (control->subtype) {
    case SUBTYPE_BITFIELD(ASSOCREQ_TYPE):
      return "Association request";
    case SUBTYPE_BITFIELD(ASSOCRESP_TYPE):
      return "Association response";
    case SUBTYPE_BITFIELD(REASSOCREQ_TYPE):
      return "Reassociation request";
    case SUBTYPE_BITFIELD(REASSOCRESP_TYPE):
      return "Reassociation response";
    case SUBTYPE_BITFIELD(PROBEREQ_TYPE):
      return "Probe request";
    case SUBTYPE_BITFIELD(PROBERESP_TYPE):
      return "Probe response";
    case SUBTYPE_BITFIELD(BEACON_TYPE):
      return "Beacon";
    case SUBTYPE_BITFIELD(ATIM_TYPE):
      return "ATIM";
    case SUBTYPE_BITFIELD(DISASSOCIATE_TYPE):
      return "Disassociation";
    case SUBTYPE_BITFIELD(AUTH_TYPE):
      return "Authentication";
    case SUBTYPE_BITFIELD(DEAUTH_TYPE):
      return "Deauthentication";
    case SUBTYPE_BITFIELD(ACTION_FRAME_TYPE):
      return "Action frame";
    default:
      return "Reserved";
    }
  }
  else if (control->type == 1) {
    switch (control->subtype) {
    case SUBTYPE_BITFIELD(BLOCKACKREQ_TYPE):
      return "Block ACK request";
    case SUBTYPE_BITFIELD(BLOCKACK_TYPE):
      return "Block ACK";
    case SUBTYPE_BITFIELD(PS_POLL_TYPE):
      return "Power Save (PS)-Poll";
    case SUBTYPE_BITFIELD(RTS_TYPE):
      return "Request To Send (RTS)";
    case SUBTYPE_BITFIELD(CTS_TYPE):
      return "Clear To Send (CTS)";
    case SUBTYPE_BITFIELD(ACK_TYPE):
      return "Acknowledgment (ACK)";
    case SUBTYPE_BITFIELD(CF_END_TYPE):
      return "Contention-Free (CF)";
    case SUBTYPE_BITFIELD(CF_END_ACK_TYPE):
      return "CF-End + CF-Ack";
    default:
      return "Reserved";
    }
  }
  else if (control->type == 2) {
    switch (control->subtype) {
    case 0:
      return "Data";
    case 1:
      return "Data + CF-Ack";
    case 2:
      return "Data + CF-Poll";
    case 3:
      return "Data + CF-Ack + CF-Poll";
    case 4:
      return "Null function (no data)";
    case 5:
      return "CF-Ack (no data)";
    case 6:
      return "CF-Poll (no data)";
    case 7:
      return "CF-Ack + CF-Poll (no data)";
    case 8:
      return "QoS Data";
    case 9:
      return "QoS Data + CF-Ack";
    case 10:
      return "QoS Data + CF-Poll";
    case 11:
      return "QoS Data + CF-Ack + CF-Poll";
    case 12:
      return "Null QoS Data";
    case 14:
      return "Null QoS Data + CF-Poll";
    case 15:
      return "Null QoS Data + CF-Ack + CF-Poll";
    default:
      return "Reserved";
    }
  }
  else if (control->type == 3) {
    return "Reserved";
  }

  return "";
}
