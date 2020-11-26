#include "PacketDecoder.h"

#include <stdio.h>
#include <pthread.h>
#include <math.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/wireless.h>
#include <termios.h>
#include <netinet/ether.h>
#include <syslog.h>

#include <string>
#include <algorithm>

//#include "wiringPiI2C.h"

#include "Application.h"
#include "pkt.h"
#include "wifi_types.h"
#include "radiotap.h"
#include "pdos80211.h"
extern "C" {
#include "create_pid_file.h"
#include "radiotap_iter.h"
#include "gps_utils.h"
}
#include "airodump-ng.h"
#include "Database.h"
#include "manufacturer.h"
#include "Packet.h"
#include "WifiMetadata.h"

namespace {
void DecodeRadiotap(const Packet* packet, void* user,
                    WifiMetadata* wifiMetadata);

void DecodeIeee80211(const Packet* packet, void* user,
                     WifiMetadata* wifiMetadata);

void ParseAddresses(const Packet* packet,
                    WifiMetadata* wifiMetadata);

int DecodeAssocReq(const uint8_t *packet_data, size_t packetLen,
                   WifiMetadata* wifiMetadata);
int DecodeBeacon(const uint8_t* packet, size_t packetLen,
                 WifiMetadata* wifiMetadata);
int DecodeProbeResp(const uint8_t* packet, size_t packetLen,
                    WifiMetadata *wifiMetadata);

void copy_ether_addr(struct ether_addr* destAddr,
                     const struct ether_addr* srcAddr);
void updateSecurity(WifiMetadata *wifiMetadata, ApplicationContext* context);
}

using namespace std;

void PacketDecoder::Decode(const Packet* packet, void* user,
                           WifiMetadata* wifiMetadata) {
    DecodeRadiotap(packet, user, wifiMetadata);
    DecodeIeee80211(packet, user, wifiMetadata);
}

namespace {
/* Decode Radiotap header */
void
DecodeRadiotap(const Packet* packet, void* user,
               WifiMetadata* wifiMetadata) {
  const uint8_t* packet_data = packet->GetData();
  ApplicationContext* context = reinterpret_cast<ApplicationContext*>(user);
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
  wifiMetadata->channel = 0;
  wifiMetadata->rate = 0;
  wifiMetadata->txPower = 0;
  wifiMetadata->antenna = 0;
  wifiMetadata->dbSignal = 0;
  wifiMetadata->dbNoise = 0;
  wifiMetadata->dbSnr = 0;
  wifiMetadata->dbmSignal = 0;
  wifiMetadata->dbmNoise = 0;
  wifiMetadata->dbmSnr = 0;
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
      wifiMetadata->rate = (*iterator.this_arg) * 5; // In units of 100 kHz
      break;

    case IEEE80211_RADIOTAP_CHANNEL:
      wifiMetadata->channel = *((uint16_t *) iterator.this_arg);
      break;

    case IEEE80211_RADIOTAP_ANTENNA:
      /* radiotap uses 0 for 1st ant */
      wifiMetadata->antenna = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DBM_TX_POWER:
      wifiMetadata->txPower = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DBM_ANTNOISE:
      wifiMetadata->dbmNoise = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
      wifiMetadata->dbmSignal = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DB_ANTNOISE:
      wifiMetadata->dbNoise = *iterator.this_arg;
      break;

    case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
      wifiMetadata->dbSignal = *iterator.this_arg;
      break;

    default:
      break;
    }
  }  /* while more rt headers */
}

/* Decode IEEE 802.11 header */
void
DecodeIeee80211(const Packet* packet, void* user,
                WifiMetadata* wifiMetadata) {
  const uint8_t* packet_data = packet->GetData();
  ApplicationContext* context = reinterpret_cast<ApplicationContext*>(user);
  size_t caplen =
    packet->GetCaptureLength(); // Length of portion present from BPF
  size_t length = packet->GetLength(); // Length of this packet off the wire

  wifiMetadata->timestamp = packet->GetTimestamp();

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

  wifiMetadata->security = 0;

  wifiMetadata->fromDs = control->from_ds;
  wifiMetadata->toDs = control->to_ds;

  ParseAddresses(packet, wifiMetadata);

  updateSecurity(wifiMetadata, context);

  wifiMetadata->ssid[0] = 0;

  if (control->type == MGMT &&
      control->subtype == SUBTYPE_BITFIELD(ASSOCREQ_TYPE)) {
    DecodeAssocReq((uint8_t*) p, caplen - radiotap_len, wifiMetadata);
  }
  else if (control->type == MGMT &&
           control->subtype == SUBTYPE_BITFIELD(BEACON_TYPE)) {
    DecodeBeacon((uint8_t*) p, caplen - radiotap_len, wifiMetadata);
  }
  else if (control->type == MGMT &&
           control->subtype == SUBTYPE_BITFIELD(PROBERESP_TYPE)) {
    DecodeProbeResp((uint8_t*) p, caplen - radiotap_len, wifiMetadata);
  }
}

void
ParseAddresses(const Packet* packet,
               WifiMetadata* wifiMetadata) {
  size_t caplen =
    packet->GetCaptureLength(); // Length of portion present from BPF
  size_t length = packet->GetLength(); // Length of this packet off the wire
  struct ieee80211_radiotap_header *radiotap_hdr =
    (struct ieee80211_radiotap_header*) packet->GetData();
  size_t radiotap_len = radiotap_hdr->it_len;

  const struct mac_header* p = (struct mac_header*) (packet + radiotap_len);
  const struct frame_control* control = (struct frame_control*) p->fc;

  // Extract MAC address
  wifiMetadata->bssidPresent = false;
  memset(&wifiMetadata->bssid, 0, ETH_ALEN);
  wifiMetadata->srcAddrPresent = false;
  memset(&wifiMetadata->srcAddr, 0, ETH_ALEN);
  wifiMetadata->destAddrPresent = false;
  memset(&wifiMetadata->destAddr, 0, ETH_ALEN);
  wifiMetadata->raPresent = false;
  memset(&wifiMetadata->ra, 0, ETH_ALEN);
  wifiMetadata->taPresent = false;
  memset(&wifiMetadata->ta, 0, ETH_ALEN);

  if (control->type == 0x01 &&
      control->subtype == SUBTYPE_BITFIELD(BLOCKACK_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->raPresent = true;
      copy_ether_addr(&wifiMetadata->ra, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      wifiMetadata->taPresent = true;
      copy_ether_addr(&wifiMetadata->ta, &p->addr2);
    }
  }
  else if (control->type == 0x01 &&
      control->subtype == SUBTYPE_BITFIELD(PS_POLL_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->bssidPresent = true;
      copy_ether_addr(&wifiMetadata->bssid, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      wifiMetadata->raPresent = true;
      copy_ether_addr(&wifiMetadata->ra, &p->addr2);
    }
  }
  else if (control->type == 0x01 &&
           control->subtype == SUBTYPE_BITFIELD(RTS_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->raPresent = true;
      copy_ether_addr(&wifiMetadata->ra, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      wifiMetadata->taPresent = true;
      copy_ether_addr(&wifiMetadata->ta, &p->addr2);
    }
  }
  else if (control->type == 0x01 &&
           control->subtype == SUBTYPE_BITFIELD(CTS_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->raPresent = true;
      copy_ether_addr(&wifiMetadata->ra, &p->addr1);
    }
  }
  else if (control->type == 0x01 &&
           control->subtype == SUBTYPE_BITFIELD(ACK_TYPE)) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->raPresent = true;
      copy_ether_addr(&wifiMetadata->ra, &p->addr1);
    }
  }
  else if (control->to_ds == 0 && control->from_ds == 0) {
    if (caplen - radiotap_len >= FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->destAddrPresent = true;
      copy_ether_addr(&wifiMetadata->destAddr, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      wifiMetadata->srcAddrPresent = true;
      copy_ether_addr(&wifiMetadata->srcAddr, &p->addr2);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 3 * sizeof(struct ether_addr)) {
      wifiMetadata->bssidPresent = true;
      copy_ether_addr(&wifiMetadata->bssid, &p->addr3);
    }
  }
  else if (control->to_ds == 0 && control->from_ds == 1) {
    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->destAddrPresent = true;
      copy_ether_addr(&wifiMetadata->destAddr, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      wifiMetadata->bssidPresent = true;
      copy_ether_addr(&wifiMetadata->bssid, &p->addr2);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 3 * sizeof(struct ether_addr)) {
      wifiMetadata->srcAddrPresent = true;
      copy_ether_addr(&wifiMetadata->srcAddr, &p->addr3);
    }
  }
  else if (control->to_ds == 1 && control->from_ds == 0) {
    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->bssidPresent = true;
      copy_ether_addr(&wifiMetadata->bssid, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      wifiMetadata->srcAddrPresent = true;
      copy_ether_addr(&wifiMetadata->srcAddr, &p->addr2);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 3 * sizeof(struct ether_addr)) {
      wifiMetadata->destAddrPresent = true;
      copy_ether_addr(&wifiMetadata->destAddr, &p->addr3);
    }
  }
  else if (control->to_ds == 1 && control->from_ds == 1) {
    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + sizeof(struct ether_addr)) {
      wifiMetadata->raPresent = true;
      copy_ether_addr(&wifiMetadata->ra, &p->addr1);
    }

    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 2 * sizeof(struct ether_addr)) {
      wifiMetadata->taPresent = true;
      copy_ether_addr(&wifiMetadata->ta, &p->addr2);
    }
    if (caplen - radiotap_len >=
        FC_LEN + DUR_LEN + 3 * sizeof(struct ether_addr)) {
      wifiMetadata->destAddrPresent = true;
      copy_ether_addr(&wifiMetadata->destAddr, &p->addr3);
    }
  }
}

/**
 * Decode Association Request message.
 *
 * @return -1 if error, 0 otherwise.
 */
int
DecodeAssocReq(const uint8_t *packet_data, size_t packetLen,
               WifiMetadata* wifiMetadata) {
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

  if (wifiMetadata->security & STD_WEP) {
    if (capab == 0x00) {
      wifiMetadata->security |= AUTH_OPN;
    }
    if (capab == 0x01) {
      wifiMetadata->security |= AUTH_PSK;
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
      memcpy(wifiMetadata->ssid, body, ssid_len);
      wifiMetadata->ssid[ssid_len] = '\0';
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
DecodeProbeResp(const uint8_t* packet_data, size_t packetLen,
                WifiMetadata* wifiMetadata) {
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
    wifiMetadata->security |= STD_WEP | ENC_WEP;
  }
  else {
    wifiMetadata->security |= STD_OPN;
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
      memcpy(wifiMetadata->ssid, body, ssid_len);
      wifiMetadata->ssid[ssid_len] = '\0';
      if (ie->len >= MAX_SSID_LEN) {
        wifiMetadata->ssid[MAX_SSID_LEN] = '\0';
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
DecodeBeacon(const uint8_t* packet_data, size_t packetLen,
             WifiMetadata* wifiMetadata) {
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
    wifiMetadata->security |= STD_WEP | ENC_WEP;
  }
  else {
    wifiMetadata->security |= STD_OPN;
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
      memcpy(wifiMetadata->ssid, body, ssid_len);
      wifiMetadata->ssid[ssid_len] = '\0';
      body += ie->len;
      break;
    case 0x30:
    case 0xDD:
      if ((ie->id == 0xDD && ie->len > 22 &&
           memcmp(body, "\x00\x50\xF2\x01\x01\x00", ETH_ALEN) == 0) ||
          (ie->id  == 0x30)) {
        wifiMetadata->security &= ~(STD_WEP | ENC_WEP);

        if (ie->id == 0xDD) {
          // WPA defined in vendor specific tag -> WPA1 support
          wifiMetadata->security |= STD_WPA;

          numuni = p[12] + (p[13] << 8);
          numauth = p[14 + 4 * numuni] + (p[15 + 4 * numuni] << 8);

          p = p + 14; // Point at first unicast cipher
        }
        else if (ie->id == 0x30) {
          wifiMetadata->security |= STD_WPA2;

          numuni = p[8] + (p[9] << 8);
          numauth = p[10 + 4 * numuni] + (p[11 + 4 * numuni] << 8);

          p += 10;
        }

        for (i = 0; i < numuni; i++) {
          switch(p[i * 4 + 3]) {
          case 0x01:
            wifiMetadata->security |= ENC_WEP;
            break;
          case 0x02:
            wifiMetadata->security |= ENC_TKIP;
            break;
          case 0x03:
            wifiMetadata->security |= ENC_WRAP;
            break;
          case 0x04:
            wifiMetadata->security |= ENC_CCMP;
            break;
          case 0x05:
            wifiMetadata->security |= ENC_WEP104;
            break;
          default:
            break;
          }
        }

        p += 2 + 4 * numuni;

        for (i = 0; i < numauth; i++) {
          switch(p[i * 4 + 3]) {
          case 0x01:
            wifiMetadata->security |= AUTH_MGT;
            break;
          case 0x02:
            wifiMetadata->security |= AUTH_PSK;
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


void copy_ether_addr(struct ether_addr *destAddr,
                     const struct ether_addr *srcAddr) {
  int i;

  for (i = 0; i < ETH_ALEN; i++) {
    destAddr->ether_addr_octet[i] = srcAddr->ether_addr_octet[i];
  }
}

void
updateSecurity(WifiMetadata* wifiMetadata, ApplicationContext* context) {
  wifiMetadata->security = 0;

  if (!wifiMetadata->bssidPresent) {
    return;
  }

  NetworkInfo_t networkInfo;
  string bssid = string(ether_ntoa(&wifiMetadata->bssid));

  NetworkDiscovery* networkDiscovery = context->GetNetworkDiscovery();

  if (networkDiscovery->GetNetwork(bssid, networkInfo)) {
    wifiMetadata->security = networkInfo.security;
  }
}
} // namespace

const char *
PacketDecoder::get_ieee80211_type(const struct frame_control* control) {
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
PacketDecoder::get_ieee80211_subtype(const struct frame_control* control) {
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
