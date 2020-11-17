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

#define SUBTYPE_BITFIELD(fc) (fc >> 12)

#define OVECCOUNT 30

#define LAST_CHANNEL 11

#define MAX_LINE_LENGTH 24

#define DEVICE_ADDRESS 0x50

#define LCD_SIZE 64

#define REG_LCD 0x00
#define REG_LCD_RESET 0x3F

#define LCD_CLEAR_SCREEN 0x0C
#define LCD_MOVE_CURSOR 0x1B

#define REG_STATUS_LED 0x41
#define REG_EXT1_LED 0x43
#define REG_EXT2_LED 0x44

#define REG_BUTTON 0x42
#define BUTTON_STATUS_SHORT 1
#define BUTTON_STATUS_LONG 2

#define DISTANCE_LOCATION_SAMPLES 10

#define DEFAULT_ACTIVITY_THRESHOLD 30

static char errbuf[PCAP_ERRBUF_SIZE];
static char payload[MAX_PACKET_SIZE];

using namespace std;

typedef enum {
  MENU_NETWORKS,
  MENU_NETWORK_DETAILS,
  MENU_CLIENT_DETAILS,
  MENU_GPS
} MenuState_t;

typedef enum {
  DETAIL_NET_MANUFACTURER,
  DETAIL_NET_FIRST_SEEN,
  DETAIL_NET_LAST_SEEN,
  DETAIL_NET_CHANNEL,
  DETAIL_NET_PACKET_COUNT,
  DETAIL_NET_LOCATION,
  DETAIL_NET_CLIENTS,
  DETAIL_NET_LAST
} NetworkDetailState_t;

inline NetworkDetailState_t
operator++(NetworkDetailState_t& ns, int) {
  const NetworkDetailState_t prev = ns;
  const int last = static_cast<int>(DETAIL_NET_LAST);
  const int i = static_cast<int>(ns);
  ns = static_cast<NetworkDetailState_t>((i + 1) % last);
  return prev;
}

typedef enum {
  DETAIL_CLIENT_MANUFACTURER,
  DETAIL_CLIENT_FIRST_SEEN,
  DETAIL_CLIENT_LAST_SEEN,
  DETAIL_CLIENT_PACKET_COUNT,
  DETAIL_CLIENT_SIGNAL_NOISE,
  DETAIL_CLIENT_LAST
} ClientDetailState_t;

inline ClientDetailState_t
operator++(ClientDetailState_t& cs, int) {
  const ClientDetailState_t prev = cs;
  const int last = static_cast<int>(DETAIL_CLIENT_LAST);
  const int i = static_cast<int>(cs);
  cs = static_cast<ClientDetailState_t>((i + 1) % last);
  return prev;
}

typedef enum {
  COMMAND_NEXT,
  COMMAND_BACK,
  COMMAND_ZOOM_IN,
  COMMAND_ZOOM_OUT,
  COMMAND_FILTER_PROTECTED,
  COMMAND_NO_FILTER,
  COMMAND_FILTER,
  COMMAND_RESET,
  COMMAND_GPS,
  COMMAND_WIFI
} Command_t;

static int opmode = 0;

static const char *PACKAGE = "wscan";

static pthread_mutex_t gpsMutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t ifMutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t channelMutex = PTHREAD_MUTEX_INITIALIZER;

static Location_t startLocation;

static Location_t lastLocation;

static double totalDistance;

static bool done = false;

static bool debugLcdDisplay;

static bool debugGps;

static NetworkIterator_t networkIterator;

static string currentClient;

static MenuState_t menuState;

static NetworkDetailState_t networkDetailState;

static ClientDetailState_t clientDetailState;

static int currentChannel;

static Command_t currentCommand;

static int skfd = -1;

static bool filter;

static bool i2c_oper;

static int i2c_fd;

static time_t lastDistanceUpdate;

static Location_t lastDistanceLocation;

static list<Location_t> distanceLocations;

static char *copy_argv(char **argv);
void radiotap_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                      const u_char *packet, PacketSummary_t *packetInfo);
void ieee802_11_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                        const u_char *packet, PacketSummary_t *packetInfo);
void parseAddresses(const struct pcap_pkthdr *pkthdr, const u_char *packet,
                    PacketSummary_t *packetInfo);
void updateSecurity(PacketSummary_t *packetInfo);
int decode_assocReq(u_char *packet, u_int32_t packetLen,
                    PacketSummary_t *packetInfo);
int decode_beacon(u_char *packet, u_int32_t packetLen,
                  PacketSummary_t *packetInfo);
int decode_probeResp(u_char *packet, u_int32_t packetLen,
                     PacketSummary_t *packetInfo);
void copy_ether_addr(struct ether_addr *destAddr, struct ether_addr *srcAddr);
const char *get_ieee80211_type(struct frame_control *control);
const char *get_ieee80211_subtype(struct frame_control *control);
u_int16_t ethernet_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                           const u_char *packet);
u_char *ip_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                   const u_char *packet);
void pcap_callback(u_char *user, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet);
void dump_payload(char *payload, size_t payload_length);
void errorlog(int opmode, const char *module, const char *message);
void initLocation();
void parseArguments(int argc, char *argv[], WscanContext_t *context);
void *monitorInterface(void *context);
void *displayMenu(void *context);
static bool isI2cOperational();
static int getButton();
static void setLed(int reg, bool state);
static void clearScreen();
static void getLocationString(char *line, const double latitude,
                              const double longitude);
static void printLine(const char *line);
static void outputLcd(const char *line, bool lineFeed);
static bool isLcdReset();
static void clearLcdReset();
static void lcdMoveCursor(int row, int column);
void *scanChannels(void *context);
void *monitorGps(void *context);
void processGpsData(gps_data_t *data, WscanContext_t *context);
void stopMonitorInterface();
int waitForKeyboardInput(unsigned int seconds);
void chooseNextNetwork();
bool chooseNextClient();
void echoOn();
void echoOff();
const char *getCommandString(Command_t command);
void chooseNextCommand();
void chooseNextNetworkDetail();
void chooseNextClientDetail();
void resetNetworks();
void resetLocation();
void updateDistance(struct gps_fix_t *gps_fix);
void getAverageLocation(Location_t& location, list<Location_t>& locations);
void applyFilter();

/*
 * copy_argv - Copy the rest of an argument string into a new buffer for
 *             processing.
 */
static char *
copy_argv(char **argv) {
  char **p;
  u_int len = 0;
  char *buf;
  char *src, *dst;

  p = argv;

  if (*p == 0)
    return 0;

  while (*p)
    len += strlen(*p++) + 1;

  buf = (char *) malloc(len);
  if (buf == NULL) {
    fprintf(stderr, "copy_argv: malloc");
    exit(1);
  }

  p = argv;
  dst = buf;
  while ((src = *p++) != NULL) {
    while ((*dst++ = *src++) != '\0')
      ;
    dst[-1] = ' ';
  }
  dst[-1] = '\0';

  return buf;
}

/* Radiotap header Handler */
void
radiotap_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                 const u_char *packet, PacketSummary_t *packetInfo) {
  WscanContext_t *context = (WscanContext_t *) user;
  u_int caplen = pkthdr->caplen; /* Length of portion present from BPF  */
  u_int length = pkthdr->len;    /* Length of this packet off the wire  */

  struct ieee80211_radiotap_header *radiotap_hdr =
    (struct ieee80211_radiotap_header *) packet;
  u_int16_t radiotap_len = radiotap_hdr->it_len;

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
  int ret = ieee80211_radiotap_iterator_init(&iterator, radiotap_hdr,
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

  fprintf(context->out, "(radiotap) ");

  if (packetInfo->channel != 0)
    fprintf(context->out, "channel %d ", packetInfo->channel);

  if (packetInfo->rate != 0)
    fprintf(context->out, "rate %d ", packetInfo->rate, currentChannel);

  if (packetInfo->dbmSignal != 0)
    fprintf(context->out, "signal (dBm) %d ", packetInfo->dbmSignal);

  if (packetInfo->dbmNoise != 0)
    fprintf(context->out, "noise (dBm) %d ", packetInfo->dbmNoise);

  if (packetInfo->dbSignal != 0)
    fprintf(context->out, "signal (dB) %d ", packetInfo->dbSignal);

  if (packetInfo->dbNoise != 0)
    fprintf(context->out, "noise (dB) %d ", packetInfo->dbNoise);
}

/* Radiotap header Handler */
void
ieee802_11_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                   const u_char *packet, PacketSummary_t *packetInfo) {
  WscanContext_t *context = (WscanContext_t *) user;
  u_int caplen = pkthdr->caplen; /* Length of portion present from BPF  */
  u_int length = pkthdr->len;    /* Length of this packet off the wire  */

  packetInfo->timestamp.tv_sec = pkthdr->ts.tv_sec;
  packetInfo->timestamp.tv_usec = pkthdr->ts.tv_usec;

  struct ieee80211_radiotap_header *radiotap_hdr =
    (struct ieee80211_radiotap_header *) packet;
  u_int16_t radiotap_len = radiotap_hdr->it_len;

  if (caplen - radiotap_len < FC_LEN) {
    char errStr[256];

    sprintf(errStr, "Packet length is less than 2 bytes: "
            "Invalid 802.11 MAC header");

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return;
  }

  struct mac_header *p = (struct mac_header *) (packet + radiotap_len);
  struct frame_control *control = (struct frame_control *) p->fc;

  fprintf(context->out, "(ieee802.11) "); 
  fprintf(context->out, "%s ", get_ieee80211_type(control));
  fprintf(context->out, "%s ", get_ieee80211_subtype(control));

#if 0
  fprintf(context->out, "SC [ %d, %d ] ", *((u_int16_t *) p->sc) & 0xf,
          *((u_int16_t *) p->sc) >> 4);
#endif

  packetInfo->security = 0;

  packetInfo->fromDs = control->from_ds;
  packetInfo->toDs = control->to_ds;

  if (packetInfo->fromDs)
    fprintf(context->out, "From DS ");

  if (packetInfo->toDs)
    fprintf(context->out, "To DS ");

  parseAddresses(pkthdr, packet, packetInfo);

  updateSecurity(packetInfo);

  if (context->eflag) {
    fprintf(context->out, "eth: ");
    if (packetInfo->bssidPresent) {
      fprintf(context->out, "BSSID %s ",
              ether_ntoa((struct ether_addr *) &packetInfo->bssid));
    }

    if (packetInfo->srcAddrPresent) {
      fprintf(context->out, "SA %s ",
              ether_ntoa((struct ether_addr *) &packetInfo->srcAddr));
    }

    if (packetInfo->destAddrPresent) {
      fprintf(context->out, "DA %s ",
              ether_ntoa((struct ether_addr *) &packetInfo->destAddr));
    }

    if (packetInfo->raPresent) {
      fprintf(context->out, "RA %s ",
              ether_ntoa((struct ether_addr *) &packetInfo->ra));
    }

    if (packetInfo->taPresent) {
      fprintf(context->out, "TA %s ",
              ether_ntoa((struct ether_addr *) &packetInfo->ta));
    }
  }

  packetInfo->ssid[0] = 0;

  if (control->type == MGMT &&
      control->subtype == SUBTYPE_BITFIELD(ASSOCREQ_TYPE)) {
    decode_assocReq((u_char *) p, caplen - radiotap_len, packetInfo);
  }
  else if (control->type == MGMT &&
           control->subtype == SUBTYPE_BITFIELD(BEACON_TYPE)) {
    decode_beacon((u_char *) p, caplen - radiotap_len, packetInfo);
  }
  else if (control->type == MGMT &&
           control->subtype == SUBTYPE_BITFIELD(PROBERESP_TYPE)) {
    decode_probeResp((u_char *) p, caplen - radiotap_len, packetInfo);
  }

  if (packetInfo->ssid[0] != '\0') {
    fprintf(context->out, "SSID %s ", packetInfo->ssid);
  }

  fprintf(context->out, "\n");
}

void
parseAddresses(const struct pcap_pkthdr *pkthdr, const u_char *packet,
               PacketSummary_t *packetInfo) {
  u_int caplen = pkthdr->caplen; /* Length of portion present from BPF  */
  u_int length = pkthdr->len;    /* Length of this packet off the wire  */
  struct ieee80211_radiotap_header *radiotap_hdr =
    (struct ieee80211_radiotap_header *) packet;
  u_int16_t radiotap_len = radiotap_hdr->it_len;

  struct mac_header *p = (struct mac_header *) (packet + radiotap_len);
  struct frame_control *control = (struct frame_control *) p->fc;

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

void
updateSecurity(PacketSummary_t *packetInfo) {
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

int
decode_assocReq(u_char *packet, u_int32_t packetLen,
                PacketSummary_t *packetInfo) {
  struct mgmt_hdr *mgmthdr;
  struct mgmt_ie_hdr *ie;
  u_char *body;
  int i;
  char tmp;

  mgmthdr = (struct mgmt_hdr *) packet;
  body = (u_char *) packet + MGMT_HDR_LEN;

  if ((body + FIELD_CAP_LEN + FIELD_LI_LEN) > (packet + packetLen)) {
    return -1;
  }

  u_char capab = *body;

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

  /* Information elements */
  while (body < (packet + packetLen)) {
    ie = (struct mgmt_ie_hdr *)body;
    body += 2;
    if ((body + ie->len) > (packet + packetLen)) {
      return -1;
    }

    switch(ie->id) {
    case IE_SSID_ID:
      tmp = body[ie->len];
      body[ie->len] = '\0';
      strncpy(packetInfo->ssid, (const char *) body, MAX_SSID_LEN);
      if (ie->len >= MAX_SSID_LEN) {
        packetInfo->ssid[MAX_SSID_LEN] = '\0';
      }
      body[ie->len] = tmp;
      body += ie->len;
      break;
    default:
      body += ie->len;
      break;
    }
  }
}

int
decode_probeResp(u_char *packet, u_int32_t packetLen,
                 PacketSummary_t *packetInfo) {
  struct mgmt_hdr *mgmthdr;
  struct mgmt_ie_hdr *ie;
  u_char *body;
  int i;
  char tmp;

  mgmthdr = (struct mgmt_hdr *) packet;
  body = (u_char *) packet + MGMT_HDR_LEN;

  if ((body + FIELD_TS_LEN + FIELD_BI_LEN + FIELD_CAP_LEN) >
      (packet + packetLen)) {
    return -1;
  }

  body += FIELD_TS_LEN;

  body += FIELD_BI_LEN;

  u_char capab = *body;

  if (capab >> 4) {
    packetInfo->security |= STD_WEP | ENC_WEP;
  }
  else {
    packetInfo->security |= STD_OPN;
  }

  body += FIELD_CAP_LEN;

  /* Information elements */
  while (body < (packet + packetLen)) {
    ie = (struct mgmt_ie_hdr *) body;
    body += 2;
    if ((body + ie->len) > (packet + packetLen)) {
      return -1;
    }

    switch(ie->id) {
    case IE_SSID_ID:
      tmp = body[ie->len];
      body[ie->len] = '\0';
      strncpy(packetInfo->ssid, (const char *) body, MAX_SSID_LEN);
      if (ie->len >= MAX_SSID_LEN) {
        packetInfo->ssid[MAX_SSID_LEN] = '\0';
      }
      body[ie->len] = tmp;
      body += ie->len;
      break;
    default:
      body += ie->len;
      break;
    }
  }
}

int
decode_beacon(u_char *packet, u_int32_t packetLen,
              PacketSummary_t *packetInfo) {
  struct mgmt_hdr *mgmthdr;
  struct mgmt_ie_hdr *ie;
  u_char *body;
  int i;
  char tmp;

  mgmthdr = (struct mgmt_hdr *) packet;
  body = (u_char *) packet + MGMT_HDR_LEN;

  if ((body + FIELD_TS_LEN + FIELD_BI_LEN + FIELD_CAP_LEN) >
      (packet + packetLen)) {
    return -1;
  }

  body += FIELD_TS_LEN;

  body += FIELD_BI_LEN;

  u_char capab = *body;

  if (capab >> 4) {
    packetInfo->security |= STD_WEP | ENC_WEP;
  }
  else {
    packetInfo->security |= STD_OPN;
  }

  body += FIELD_CAP_LEN;

  /* Information elements */
  while (body < (packet + packetLen)) {
    u_char *p = body;
    ie = (struct mgmt_ie_hdr *) body;
    body += 2;
    if ((body + ie->len) > (packet + packetLen)) {
      return -1;
    }

    int numuni;
    int numauth;
    int i;

    switch(ie->id) {
    case IE_SSID_ID:
      tmp = body[ie->len];
      body[ie->len] = '\0';
      strncpy(packetInfo->ssid, (const char *) body, MAX_SSID_LEN);
      body[ie->len] = tmp;
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
}

void copy_ether_addr(struct ether_addr *destAddr, struct ether_addr *srcAddr) {
  int i;

  for (i = 0; i < ETH_ALEN; i++) {
    destAddr->ether_addr_octet[i] = srcAddr->ether_addr_octet[i];
  }
}

const char *
get_ieee80211_type(struct frame_control *control) {
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
get_ieee80211_subtype(struct frame_control *control) {
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

/* Ethernet Handler */
u_int16_t
ethernet_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                 const u_char *packet) {
  WscanContext_t *context = (WscanContext_t *) user;
  u_int caplen = pkthdr->caplen; /* Length of portion present from bpf  */
  u_int length = pkthdr->len;    /* Length of this packet off the wire  */
  struct ether_header *eptr;     /* net/ethernet.h                      */
  u_short ether_type;            /* The type of packet (we return this) */
  eptr = (struct ether_header *) packet;
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
u_char *
ip_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
           const u_char *packet) {
  WscanContext_t *context = (WscanContext_t *) user;
  const struct nread_ip *ip;   /* Packet structure      */ 
  const struct tcphdr *tcp;    /* TCP structure         */
  u_int length = pkthdr->len;  /* Packet header length  */
  u_int hlen, off, version;    /* Offset, version       */
  int len;                     /* Length holder         */

  ip = (struct nread_ip *) (packet + sizeof(struct ether_header));
  length -= sizeof(struct ether_header);
  tcp = (struct tcphdr *)
    (packet + sizeof(struct ether_header) + sizeof(struct nread_ip));
   
  hlen    = IP_HL(ip);         /* get header length */ 
  len     = ntohs(ip->ip_len); /* get packet length */
  version = IP_V(ip);          /* get ip version    */

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
          /* There is TCP/UDP payload */
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

void
dump_payload(char *payload, size_t payload_length) {
  size_t i;
  for (i = 0; i < payload_length; i++) {
    char c = payload[i];
    if (c < 32 || c > 126)
      fputc('.', stdout);
    else
      fputc(c, stdout);
  }
}

/* Callback */
void
pcap_callback(u_char *user, const struct pcap_pkthdr *pkthdr,
              const u_char *packet) {
  WscanContext_t *context;
  PacketSummary_t packetSummary;
  int i;

  reportActivity(ACTIVITY_MONITOR_INTERFACE);

  context = (WscanContext_t *) user;

  if (context->dumper != NULL) {
    pcap_dump((u_char *) context->dumper, pkthdr, packet);
  }

  if (context->vflag > 3) {
    for (i = 0; i < pkthdr->len; i++) {
      fprintf(context->out, "%02x ", packet[i]);
      if (i % 16 == 15)
        fprintf(context->out, "\n");
    }

    if (i % 16 != 0) {
      fprintf(context->out, "\n");
    }
  }

  if (context != NULL && context->datalink == DLT_IEEE802_11_RADIO) {
    radiotap_handler(user, pkthdr, packet, &packetSummary);
    ieee802_11_handler(user, pkthdr, packet, &packetSummary);

    updateNetworkResources(context, &packetSummary);

    if (isEndNetworkIterator(networkIterator) && getNetworkCount() > 0) {
      beginNetworkIterator(networkIterator);
    }
  }

  u_int16_t type = ethernet_handler(user, pkthdr, packet);

  if (type == ETHERTYPE_IP) {
    ip_handler(user, pkthdr, packet);
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

void
parseArguments(int argc, char *argv[], WscanContext_t *context) {
  context->dev = NULL;
  context->eflag = 0;
  context->interactive = false;
  context->npkts = -1;
  context->oper = NULL;
  context->vflag = 3;
  context->out = NULL;
  context->outPcap = NULL;
  context->dumper = NULL;
  context->priority = LOG_USER | LOG_LOCAL3 | LOG_INFO;
  context->activityThreshold = DEFAULT_ACTIVITY_THRESHOLD;

  debugLcdDisplay = false;
  debugGps = false;

  while (1) {
    static struct option long_options[] = {
      {"ethernet",           no_argument,       0, 'e'},
      {"interface",          required_argument, 0, 'i'},
      {"interactive",        no_argument,       0, 'I'},
      {"output",             required_argument, 0, 'o'},
      {"output-pcap",        required_argument, 0, 'w'},
      {"polls",              required_argument, 0, 'p'},
      {"verbose",            required_argument, 0, 'v'},
      {"debug-lcd",          no_argument,       0, 'l'},
      {"debug-gps",          no_argument,       0, 'g'},
      {"activity-threshold", required_argument, 0, 't'},
      {0,0,0,0}
    };

    int option_index = 0;

    int c = getopt_long(argc, argv, "ei:Ip:v:o:w:lg", long_options,
                        &option_index);

    if (c == -1)
      break;

    switch (c) {
      case 'e':
        context->eflag = 1;
        break;
      case 'i':
        context->dev = optarg;
        break;
      case 'I':
        context->interactive = true;
        break;
      case 'p':
        context->npkts = atoi(optarg);
        break;
      case 'o':
        context->out = fopen(optarg, "w");
        break;
      case 'w':
        context->outPcap = fopen(optarg, "w");
        break;
      case 'l':
        debugLcdDisplay = true;
        break;
      case 'g':
        debugGps = true;
        break;
      case 't':
        context->activityThreshold = atoi(optarg);
        break;
      default:
        break;
    }
  }

  if (context->out == NULL) {
    context->out = fopen("/dev/null", "w");
  }

  argc -= optind;
  argv += optind;

  context->oper = copy_argv(argv);
}

int
main(int argc, char **argv) {
  WscanContext_t context;
  pthread_t gpsThreadId;
  pthread_t interfaceThreadId;
  pthread_t displayThreadId;
  pthread_t scanChannelsThreadId;
  pthread_t journalWirelessInfoThreadId;
  pthread_t heartbeatThreadId;

  createPidFile("wscand", "/var/run/wscand.pid", CPF_CLOEXEC);

  parseArguments(argc, argv, &context);

  initNetworkDiscovery();

  if (getuid()) {
    fprintf(stderr, "Error! Must be root... Exiting\n");
    return(1);
  }

  pthread_create(&gpsThreadId, NULL, monitorGps, &context);

  pthread_create(&interfaceThreadId, NULL, monitorInterface, &context);

  pthread_create(&displayThreadId, NULL, displayMenu, &context);

  pthread_create(&scanChannelsThreadId, NULL, scanChannels, &context);

  pthread_create(&journalWirelessInfoThreadId, NULL, journalWirelessInformation,
                 &context);

  pthread_create(&heartbeatThreadId, NULL, monitorHeartbeat, &context);

  pthread_join(gpsThreadId, NULL);

  pthread_join(interfaceThreadId, NULL);

  pthread_join(displayThreadId, NULL);

  pthread_join(scanChannelsThreadId, NULL);

  pthread_join(journalWirelessInfoThreadId, NULL);

  pthread_join(heartbeatThreadId, NULL);

  displayNetworks(&context);

  releaseNetworkResources();

  return 0;
}

void *
monitorInterface(void *ctx) {
  WscanContext_t *context = (WscanContext_t *) ctx;

  if (context->dev == NULL) {
    context->dev = pcap_lookupdev(errbuf);
  }

  if (context->dev == NULL) {
    fprintf(stderr, "%s\n", errbuf);

    stopMonitorInterface();

    return NULL;
  }

  fprintf(context->out, "Monitoring device %s\n", context->dev);

  pcap_t *descr = pcap_open_live(context->dev, BUFSIZ, 1, 1000, errbuf);

  if (descr == NULL) {
    fprintf(context->out, "pcap_open_live(): %s\n", errbuf);
    
    stopMonitorInterface();
    
    return NULL;
  }

  if (context->outPcap != NULL) {
    context->dumper = pcap_dump_fopen(descr, context->outPcap);
  }

  context->datalink = pcap_datalink(descr);

  bpf_u_int32 net;

  bpf_u_int32 mask;

  pcap_lookupnet(context->dev, &net, &mask, errbuf);

  struct in_addr addr;

  addr.s_addr = net;

  fprintf(context->out, "Monitoring IP %s on data link %d\n", inet_ntoa(addr),
          context->datalink);

  struct bpf_program filter;

  if (context->oper) {
    fprintf(context->out, "Setting filter %s\n", context->oper);
    if (pcap_compile(descr, &filter, context->oper, 0, mask) == -1) {
      errorlog(opmode, PACKAGE, "Error calling pcap_compile");
      pcap_perror(descr, context->dev);
      exit(1);
    }

    if (pcap_setfilter(descr, &filter))  {
      errorlog(opmode, PACKAGE, "Error setting filter");
      exit(1);
    }
  }

  context->descr = descr;

  pcap_loop(descr, context->npkts, pcap_callback,
            (u_char *) context); /* Loop pcap */

  if (context->dumper != NULL) {
    pcap_dump_close(context->dumper);
  }

  stopMonitorInterface();

  return NULL;
}

void *
displayMenu(void *ctx) {
  WscanContext_t *context = (WscanContext_t *) ctx;
  char line[MAX_LINE_LENGTH + 2];
  bool lastLedOpenState;
  bool lastLedWepState;
  bool lastLedWpaState;
  ostringstream lastZone1, lastZone2, lastZone3, lastZone4, lastZone5,
    lastZone6;
  ostringstream zone1, zone2, zone3, zone4, zone5, zone6;

  i2c_fd = wiringPiI2CSetup(DEVICE_ADDRESS);

  menuState = MENU_NETWORKS;
  currentCommand = COMMAND_NEXT;
  filter = false;
  lastLedOpenState = false;
  lastLedWepState = false;
  lastLedWpaState = false;

  beginNetworkIterator(networkIterator);

  i2c_oper = isI2cOperational();

  if (!i2c_oper) {
    char errStr[256];

    sprintf(errStr, "I2C failure: Disabling interactions with IgORE board");

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    if (context->interactive) {
      fprintf(stderr, "%s\n", errStr);
    }
  }

  setLed(REG_STATUS_LED, lastLedOpenState);
  setLed(REG_EXT2_LED, lastLedWepState);
  setLed(REG_EXT1_LED, lastLedWpaState);

  lastZone1.str("");
  lastZone2.str("");
  lastZone3.str("");
  lastZone4.str("");
  lastZone5.str("");

  clearScreen();

  for ( ; ; ) {
    if (!isMonitorInterface()) {
      break;
    }

    reportActivity(ACTIVITY_DISPLAY_MENU);

    if (isLcdReset()) {
      lastZone1.str("");
      lastZone2.str("");
      lastZone3.str("");
      lastZone4.str("");
      lastZone5.str("");
      clearLcdReset();
      clearScreen();
    }

    string currentNetworkSnapshot;
    uint32_t networkCountSnapshot;
    string currentClientSnapshot;

    networkCountSnapshot = getNetworkCount();

    getNetworkIteratorBssid(networkIterator, currentNetworkSnapshot);
    currentClientSnapshot = currentClient;

    bool ledOpenState = isOpenNetwork(context);
 
    if (ledOpenState != lastLedOpenState) {
      setLed(REG_STATUS_LED, ledOpenState);
    }

    lastLedOpenState = ledOpenState;

    bool ledWepState = isWepNetwork(context);
 
    if (ledWepState != lastLedWepState) {
      setLed(REG_EXT2_LED, ledWepState);
    }

    lastLedWepState = ledWepState;

    bool ledWpaState = isWpaNetwork(context);
 
    if (ledWpaState != lastLedWpaState) {
      setLed(REG_EXT1_LED, ledWpaState);
    }

    lastLedWpaState = ledWpaState;

    zone1.str("");
    zone2.str("");
    zone3.str("");
    zone4.str("");
    zone5.str("");
    zone6.str("");

    zone6 << getCommandString(currentCommand);

    NetworkInfo_t networkInfo;
    bool networkFound = getNetwork(currentNetworkSnapshot, networkInfo);

    if ((menuState == MENU_NETWORKS || menuState == MENU_NETWORK_DETAILS) &&
        !networkFound) {
        zone3 << networkCountSnapshot;
    }
    else if (menuState == MENU_NETWORKS || menuState == MENU_NETWORK_DETAILS) {
      if (networkInfo.ssid.size() > 16) {
        zone1 << networkInfo.ssid.substr(0, 13) << "...";
      }
      else {
        zone1 << networkInfo.ssid;
      }

      zone2 << getSecurityString(networkInfo.security);
      if (networkCountSnapshot < 100) {
          zone3 << networkCountSnapshot;
      }
      else {
          zone3 << "*" << (networkCountSnapshot % 10);
      }

      if (menuState == MENU_NETWORKS) {
        zone4 << currentNetworkSnapshot;
        const char *signalStr = getBestClientSignal(currentNetworkSnapshot);
        if (signalStr != NULL) {
          zone5 << signalStr;
        }
      }
      else if (menuState == MENU_NETWORK_DETAILS) {
        switch(networkDetailState) {
        case DETAIL_NET_MANUFACTURER:
          {
            struct ether_addr *addr =
              ether_aton(currentNetworkSnapshot.c_str());
            zone4 << getManufacturer(addr);
          }
          break;
        case DETAIL_NET_FIRST_SEEN:
          {
            struct tm *brokenDownTime = gmtime(&networkInfo.firstSeen);
            char timeStr[MAX_LINE_LENGTH + 1];
            sprintf(timeStr, "F: %04d-%02d-%02d %02d:%02d:%02d",
                    brokenDownTime->tm_year + 1900, brokenDownTime->tm_mon + 1,
                    brokenDownTime->tm_mday, brokenDownTime->tm_hour,
                    brokenDownTime->tm_min, brokenDownTime->tm_sec);
            zone4 << timeStr;
          }
          break;
        case DETAIL_NET_LAST_SEEN:
          {
            struct tm *brokenDownTime = gmtime(&networkInfo.lastSeen);
            char timeStr[MAX_LINE_LENGTH + 1];
            sprintf(timeStr, "L: %04d-%02d-%02d %02d:%02d:%02d",
                    brokenDownTime->tm_year + 1900, brokenDownTime->tm_mon + 1,
                    brokenDownTime->tm_mday, brokenDownTime->tm_hour,
                    brokenDownTime->tm_min, brokenDownTime->tm_sec);
            zone4 << timeStr;
          }
          break;
        case DETAIL_NET_CHANNEL:
          char channelStr[MAX_LINE_LENGTH + 1];
          sprintf(channelStr, "Channel: %-3d", networkInfo.channel);
          zone4 << channelStr;
          break;
        case DETAIL_NET_PACKET_COUNT:
          char packetStr[MAX_LINE_LENGTH + 1];
          sprintf(packetStr, "Packets: %-10d",
                  networkInfo.packetCount);
          zone4 << packetStr;
          break;
        case DETAIL_NET_LOCATION:
          char locationStr[MAX_LINE_LENGTH + 1];
          getLocationString(locationStr, networkInfo.location.latitude,
                            networkInfo.location.longitude);
          zone4 << locationStr;
          break;
        case DETAIL_NET_CLIENTS:
          if (currentClientSnapshot.empty()) {
            chooseNextClient();
            currentClientSnapshot = currentClient;
          }

          zone4 << currentClientSnapshot;
          break;
        }
      }
    }

    if (menuState == MENU_CLIENT_DETAILS) {
      zone1 << currentClientSnapshot.c_str();

      ClientInfo_t client;
      bool clientFound = getClient(currentNetworkSnapshot,
                                   currentClientSnapshot, client);

      switch(clientDetailState) {
      case DETAIL_CLIENT_MANUFACTURER:
        {
          struct ether_addr *addr =
            ether_aton(currentClientSnapshot.c_str());
          zone4 << getManufacturer(addr);
        }
        break;
      case DETAIL_CLIENT_FIRST_SEEN:
        {
          struct tm *brokenDownTime = gmtime(&client.firstSeen);
          char timeStr[MAX_LINE_LENGTH + 1];
          sprintf(timeStr, "F: %04d-%02d-%02d %02d:%02d:%02d",
                  brokenDownTime->tm_year + 1900, brokenDownTime->tm_mon + 1,
                  brokenDownTime->tm_mday, brokenDownTime->tm_hour,
                  brokenDownTime->tm_min, brokenDownTime->tm_sec);
          zone4 << timeStr;
        }
        break;
      case DETAIL_CLIENT_LAST_SEEN:
        {
          struct tm *brokenDownTime = gmtime(&client.lastSeen);
          char timeStr[MAX_LINE_LENGTH + 1];
          sprintf(timeStr, "L: %04d-%02d-%02d %02d:%02d:%02d",
                  brokenDownTime->tm_year + 1900, brokenDownTime->tm_mon + 1,
                  brokenDownTime->tm_mday, brokenDownTime->tm_hour,
                  brokenDownTime->tm_min, brokenDownTime->tm_sec);
          zone4 << timeStr;
        }
        break;
      case DETAIL_CLIENT_PACKET_COUNT:
        char packetStr[MAX_LINE_LENGTH + 1];
        sprintf(packetStr, "Packets: %-10d", client.packetCount);
        zone4 << packetStr;
        break;
      case DETAIL_CLIENT_SIGNAL_NOISE:
        if (client.dbmSignal != 0) {
          zone4 << "Signal: " << ((int32_t) client.dbmSignal) << " ";
        }
        if (client.dbmNoise != 0) {
          zone4 << "Noise: " <<  ((int32_t) client.dbmNoise);
        }
        break;
      default:
        break;
      }
    }

    if (menuState == MENU_GPS) {
      double latitude, longitude;

      pthread_mutex_lock(&gpsMutex);
      latitude = lastLocation.latitude;
      longitude = lastLocation.longitude;
      pthread_mutex_unlock(&gpsMutex);

      char locationStr[MAX_LINE_LENGTH + 1];
      getLocationString(locationStr, latitude, longitude);
      zone1 << locationStr;

      char distanceStr[MAX_LINE_LENGTH + 1];
      sprintf(distanceStr, "Distance: %.3f", totalDistance);
      zone4 << distanceStr;
    }

    if (zone2.str().compare(lastZone2.str()) != 0) {
      lcdMoveCursor(0, 17);
      sprintf(line, "%-5s", zone2.str().c_str());
      printLine(line);
    }

    if (zone3.str().compare(lastZone3.str()) != 0) {
      lcdMoveCursor(0, 22);
      sprintf(line, "%2s", zone3.str().c_str());
      printLine(line);
    }

    if (zone1.str().compare(lastZone1.str()) != 0) {
      lcdMoveCursor(0, 0);
      if (zone2.str().empty()) {
        sprintf(line, "%-24s", zone1.str().c_str());
      }
      else {
        sprintf(line, "%-17s", zone1.str().c_str());
      }
      printLine(line);
    }

    if (zone5.str().compare(lastZone5.str()) != 0) {
      lcdMoveCursor(1, 18);
      sprintf(line, "%-3s", zone5.str().c_str());
      printLine(line);
    }

    if (zone4.str().compare(lastZone4.str()) != 0) {
      lcdMoveCursor(1, 0);
      if (zone5.str().empty()) {
        sprintf(line, "%-23s", zone4.str().c_str());
      }
      else {
        sprintf(line, "%-18s", zone4.str().c_str());
      }

      printLine(line);
    }

    if (zone6.str().compare(lastZone6.str()) != 0) {
      lcdMoveCursor(1, 23);
      printLine(zone6.str().c_str());
    }

    if (context->interactive &&
        (zone1.str().compare(lastZone1.str()) != 0 ||
         zone2.str().compare(lastZone2.str()) != 0 ||
         zone3.str().compare(lastZone3.str()) != 0 ||
         zone4.str().compare(lastZone4.str()) != 0 ||
         zone5.str().compare(lastZone5.str()) != 0 ||
         zone6.str().compare(lastZone6.str()) != 0)) {
      if (zone2.str().empty()) {
        fprintf(stdout, "%-21s %2s\n", zone1.str().c_str(),
                zone3.str().c_str());
      }
      else {
        fprintf(stdout, "%-16s %-4s %2s\n", zone1.str().c_str(),
                zone2.str().c_str(), zone3.str().c_str());
      }

      if (zone5.str().empty()) {
        fprintf(stdout, "%-23s%1s\n", zone4.str().c_str(), zone6.str().c_str());
      }
      else {
        fprintf(stdout, "%-18s %-3s %1s\n", zone4.str().c_str(),
                zone5.str().c_str(), zone6.str().c_str());
      }
    }

    lastZone1.str(zone1.str());
    lastZone2.str(zone2.str());
    lastZone3.str(zone3.str());
    lastZone4.str(zone4.str());
    lastZone5.str(zone5.str());
    lastZone6.str(zone6.str());

    echoOff();

    char c;

    int status = getButton();

    if (status == BUTTON_STATUS_SHORT) {
      c = '.';
    }
    else if (status == BUTTON_STATUS_LONG) {
      c = ' ';
    }

    if (status != BUTTON_STATUS_SHORT && status != BUTTON_STATUS_LONG) {
      if  (context->interactive) {
        int status = waitForKeyboardInput(1);

        if (status != 1) {
          continue;
        }

        c = getc(stdin);
      }
      else {
        continue;
      }
    }

    if (c == 'x') {
      pcap_breakloop(context->descr);

      stopMonitorInterface();

      continue;
    }

    if (c == ' ') {
      // Long button pressed: Select next command.
      chooseNextCommand();

      continue;
    }

    // Short button pressed: Execute current command.
    switch(currentCommand) {
    case COMMAND_NEXT:
      if (menuState == MENU_NETWORKS) {
        chooseNextNetwork();
      }
      else if (menuState == MENU_NETWORK_DETAILS) {
        if (networkDetailState == DETAIL_NET_CLIENTS) {
          if (!chooseNextClient()) {
            chooseNextNetworkDetail();
          }
        }
        else {
          chooseNextNetworkDetail();
        }
      }
      else {
        chooseNextClientDetail();
      }
      break;
    case COMMAND_ZOOM_IN:
      if (menuState == MENU_NETWORKS) {
        menuState = MENU_NETWORK_DETAILS;
        networkDetailState = DETAIL_NET_MANUFACTURER;
        currentClient = "";
      }
      else if (menuState == MENU_NETWORK_DETAILS) {
        if (networkDetailState == DETAIL_NET_CLIENTS) {
          menuState = MENU_CLIENT_DETAILS;
          clientDetailState = DETAIL_CLIENT_MANUFACTURER;
        }
      }
      currentCommand = COMMAND_NEXT;
      break;
    case COMMAND_ZOOM_OUT:
      if (menuState == MENU_NETWORK_DETAILS) {
        menuState = MENU_NETWORKS;
      }
      else {
        menuState = MENU_NETWORK_DETAILS;
      }
      currentCommand = COMMAND_NEXT;
      break;
    case COMMAND_FILTER_PROTECTED:
      filter = true;
      applyFilter();
      currentCommand = COMMAND_NO_FILTER;
      break;
    case COMMAND_NO_FILTER:
      filter = false;
      currentCommand = COMMAND_FILTER_PROTECTED;
      break;
    case COMMAND_RESET:
      if (menuState == MENU_GPS) {
        resetLocation();
        currentCommand = COMMAND_WIFI;
      }
      else {
        resetNetworks();
        currentCommand = COMMAND_NEXT;
      }
      break;
    case COMMAND_GPS:
      menuState = MENU_GPS;
      currentCommand = COMMAND_WIFI;
      break;
    case COMMAND_WIFI:
      menuState = MENU_NETWORKS;
      currentCommand = COMMAND_NEXT;
      break;
    }
  }

  echoOn();

  return NULL;
}

static bool
isI2cOperational() {
  int status = wiringPiI2CReadReg8(i2c_fd, REG_BUTTON);

  return status != -1;
}

static int
getButton() {
  char errStr[80];

  if (!i2c_oper) {
    return 0;
  }

  int regValue = wiringPiI2CReadReg8(i2c_fd, REG_BUTTON);

  if (regValue == -1) {
    sprintf(errStr, "Error reading register 0x%02X from I2C slave device "
            "0x%02X", REG_BUTTON, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return 0;
  }

  int status = wiringPiI2CWriteReg8(i2c_fd, REG_BUTTON, 0);

  if (status == -1) {
    sprintf(errStr, "Error writing register 0x%02X on I2C slave device "
            "0x%02X", REG_BUTTON, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return 0;
  }

  return regValue;
}

static void
setLed(int reg, bool state) {
  if (!i2c_oper) {
    return;
  }

  int status = wiringPiI2CWriteReg8(i2c_fd, reg, state);

  if (status == -1) {
    char errStr[80];

    sprintf(errStr, "Failed writing to register 0x%02X on I2C slave device "
            "0x%02X", REG_STATUS_LED, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);
  }
}

static void
clearScreen() {
  char str[2];

  str[0] = LCD_CLEAR_SCREEN;
  str[1] = '\0';

  outputLcd(str, false);
}

static void
getLocationString(char *line, const double latitude, const double longitude) {
  char str[MAX_LINE_LENGTH + 2];
  if (!isnan(latitude)) {
    sprintf(line, "%2.6lf ", latitude);
  }
  else {
    sprintf(line, "-- ");
  }
  if (!isnan(longitude)) {
    sprintf(str, "%2.6lf", longitude);
    strcat(line, str);
  }
  else {
    sprintf(str, "--");
    strcat(line, str);
  }
}

static void
printLine(const char *line) {
  outputLcd(line, false);
}

static bool
isLcdReset() {
  if (!i2c_oper) {
    return false;
  }

  int regValue = wiringPiI2CReadReg8(i2c_fd, REG_LCD_RESET);

  if (regValue == -1) {
    char errStr[80];

    sprintf(errStr, "Error reading register 0x%02X from I2C slave device "
            "0x%02X", REG_LCD_RESET, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return false;
  }

  if (regValue != 0) {
    if (debugLcdDisplay) {
      char debugStr[80];

      sprintf(debugStr, "LCD Display: Detected reset");

      syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr);
    }

    return true;
  }

  return false;
}

static void
clearLcdReset() {
  if (!i2c_oper) {
    return;
  }

  int status = wiringPiI2CWriteReg8(i2c_fd, REG_LCD_RESET, 0x00);

  if (status == -1) {
    char errStr[80];

    sprintf(errStr, "Error writing register 0x%02X on I2C slave device "
            "0x%02X", REG_LCD_RESET, DEVICE_ADDRESS);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return;
  }

  if (debugLcdDisplay) {
    char debugStr[80];

    sprintf(debugStr, "LCD Display: Clear");

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr);
  }
}

static void
lcdMoveCursor(int row, int column) {
  if (!i2c_oper) {
    return;
  }

  if (debugLcdDisplay) {
    char debugStr[80];

    sprintf(debugStr, "LCD Display: Move cursor to row %d, column %d", row,
            column);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr);
  }

  char cmd[64];

  sprintf(cmd, "sudo i2cset -y 1 0x%02x 0x%02x 0x%02x 0x%02x 0x00 i",
          DEVICE_ADDRESS, REG_LCD + 1, row, column);

  system(cmd);

  sprintf(cmd, "sudo i2cset -y 1 0x%02x 0x%02x 0x%02x i",
          DEVICE_ADDRESS, REG_LCD, LCD_MOVE_CURSOR);

  system(cmd);
}

static void
outputLcd(const char *line, bool lineFeed) {
  if (!i2c_oper) {
    return;
  }

  if (debugLcdDisplay) {
    char debugStr[80];

    snprintf(debugStr, 80, "LCD Display: Output '%s'", line);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr);
  }

  char cmd[512];
  char str[8];
  int len = strlen(line);
  int i;

  if (len > LCD_SIZE - 1) {
    len = LCD_SIZE - 1;
  }

  sprintf(cmd, "sudo i2cset -y 1 0x%02x 0x%02x ", DEVICE_ADDRESS, REG_LCD);

  for (i = 0; i < len; i++) {
    sprintf(str, "0x%02x ", line[i]);
    strcat(cmd, str);
  }

  if (lineFeed) {
    strcat(cmd, "0x0a ");
  }

  strcat(cmd, "0x00 i");

  system(cmd);
}

void *
scanChannels(void *ctx) {
  WscanContext_t *context = (WscanContext_t *) ctx;

  iwconfig_open();

  pthread_mutex_lock(&channelMutex);
  currentChannel = 1;
  pthread_mutex_unlock(&channelMutex);
  
  for ( ; ; ) {
    if (!isMonitorInterface()) {
      break;
    }

    reportActivity(ACTIVITY_SCAN_CHANNEL);

    setChannel(context->dev, currentChannel);

    usleep(100000);

    pthread_mutex_lock(&channelMutex);
    currentChannel = (currentChannel % LAST_CHANNEL) + 1;
    pthread_mutex_unlock(&channelMutex);
  }

  iwconfig_close();

  return NULL;
}

void
errorlog(int opmode, const char *module, const char *message) {
  fprintf(stderr, "%s: %s\n", module, message);
}

void
initLocation() {
  pthread_mutex_lock(&gpsMutex);

  totalDistance = 0.0;

  startLocation.latitude = NAN;
  startLocation.longitude = NAN;
  startLocation.altitude = NAN;
  startLocation.epx = NAN;
  startLocation.epy = NAN;
  startLocation.timestamp = 0;

  lastLocation.latitude = NAN;
  lastLocation.longitude = NAN;
  lastLocation.altitude = NAN;
  lastLocation.epx = NAN;
  lastLocation.epy = NAN;
  lastLocation.timestamp = 0;

  lastDistanceLocation.latitude = NAN;
  lastDistanceLocation.longitude = NAN;
  lastDistanceLocation.altitude = NAN;
  lastDistanceLocation.epx = NAN;
  lastDistanceLocation.epy = NAN;
  lastDistanceLocation.timestamp = 0;

  pthread_mutex_unlock(&gpsMutex);
}

void *
monitorGps(void *ctx)
{
  WscanContext_t *context = (WscanContext_t *) ctx;

  initLocation();

  gpsmm gps_rec("localhost", DEFAULT_GPSD_PORT);

  if (gps_rec.stream(WATCH_ENABLE|WATCH_JSON) == NULL) {
    cerr << "Daemon gpsd is not running.\n";
    return NULL;
  }

  for ( ; ; ) {
    if (!isMonitorInterface()) {
      break;
    }

    reportActivity(ACTIVITY_MONITOR_GPS);

    struct gps_data_t* newdata;

    if (!gps_rec.waiting(50000000))
      continue;

    if ((newdata = gps_rec.read()) == NULL) {
      cerr << "Read error.\n";
      return NULL;
    }
    else {
      processGpsData(newdata, context);
    }
  }

  return NULL;
}

void
processGpsData(gps_data_t *data, WscanContext_t *context) {
  struct gps_fix_t *gps_fix;

  gps_fix = &data->fix;

  pthread_mutex_lock(&gpsMutex);

  updateDistance(gps_fix);

  if (!isnan(gps_fix->latitude)) {
    if (isnan(startLocation.latitude)) {
      startLocation.latitude = gps_fix->latitude;
    }

    lastLocation.latitude = gps_fix->latitude;
  }

  if (!isnan(gps_fix->longitude)) {
    if (isnan(startLocation.longitude)) {
      startLocation.longitude = gps_fix->longitude;
    }

    lastLocation.longitude = gps_fix->longitude;
  }

  if (!isnan(gps_fix->altitude)) {
    if (isnan(startLocation.altitude)) {
      startLocation.altitude = gps_fix->altitude;
    }
    lastLocation.altitude = gps_fix->altitude;
  }

  if (!isnan(gps_fix->epx)) {
    lastLocation.epx = gps_fix->epx;
  }

  if (!isnan(gps_fix->epy)) {
    lastLocation.epy = gps_fix->epy;
  }

  if (startLocation.timestamp == 0) {
    startLocation.timestamp = gps_fix->time;
  }

  lastLocation.timestamp = gps_fix->time;

  pthread_mutex_unlock(&gpsMutex);

  // Output GPS information.
  if (!isnan(gps_fix->latitude) || !isnan(gps_fix->longitude) ||
      !isnan(gps_fix->altitude)) {
    fprintf(context->out, "GPS:\n");
  }

  if (!isnan(gps_fix->latitude)) {
    fprintf(context->out, "  Latitude = %lf\n", gps_fix->latitude);
  }

  if (!isnan(gps_fix->longitude)) {
    fprintf(context->out, "  Longitude = %lf\n", gps_fix->longitude);
  }

  if (!isnan(gps_fix->altitude)) {
    fprintf(context->out, "  Altitude = %lf\n", gps_fix->altitude);
  }
}

void
setCurrentLocation(Location_t *location) {
  pthread_mutex_lock(&gpsMutex);

  location->latitude = lastLocation.latitude;

  location->longitude = lastLocation.longitude;

  location->altitude = lastLocation.altitude;

  location->epx = lastLocation.epx;

  location->epy = lastLocation.epy;

  location->timestamp = lastLocation.timestamp;

  pthread_mutex_unlock(&gpsMutex);
}

int
setChannel(char *ifName, int channel) {
  if (skfd < 0) {
    return -1;
  }

  struct iwreq wrq;

  /* Set dev name */
  strncpy(wrq.ifr_name, ifName, IFNAMSIZ);

  double freq;

  freq = (double) channel;

  float2freq(freq, &(wrq.u.freq));

  if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
    char errStr[256];

    snprintf(errStr, 256, "SIOCSIWFREQ: %s", strerror(errno));

    syslog(LOG_USER | LOG_LOCAL3 | LOG_ERR, errStr);

    return(-1);
  }

  return(0);
}

int
iwconfig_open() {
  skfd = -1; /* Generic raw socket desc. */

  /* Create a channel to the NET kernel. */
  if ((skfd = sockets_open()) < 0) {
    perror("socket");
    return(-1);
  }

  return(0);
}

/************************ SOCKET SUBROUTINES *************************/

/*------------------------------------------------------------------*/
/*
 * Open a socket.
 * Depending on the protocol present, open the right socket. The socket
 * will allow us to talk to the driver.
 */
int
sockets_open(void)
{
  int ipx_sock = -1;		/* IPX socket			*/
  int ax25_sock = -1;		/* AX.25 socket			*/
  int inet_sock = -1;		/* INET socket			*/
  int ddp_sock = -1;		/* Appletalk DDP socket		*/

  inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
  ipx_sock = socket(AF_IPX, SOCK_DGRAM, 0);
  ax25_sock = socket(AF_AX25, SOCK_DGRAM, 0);
  ddp_sock = socket(AF_APPLETALK, SOCK_DGRAM, 0);

  /*
   * Now pick any (exisiting) useful socket family for generic queries
   */
  if (inet_sock!=-1)
    return inet_sock;
  if (ipx_sock!=-1)
    return ipx_sock;
  if (ax25_sock!=-1)
    return ax25_sock;
  /*
   * If this is -1 we have no known network layers and its time to jump.
   */

  return ddp_sock;
}

void
iwconfig_close() {
  /* Close the socket. */
  close(skfd);
}

/********************** FREQUENCY SUBROUTINES ***********************/

/*------------------------------------------------------------------*/
/*
 * Convert a floating point to our internal representation of
 * frequencies.
 * The kernel doesn't want to hear about floating point, so we use
 * this custom format instead.
 */
void
float2freq(double in,
	   iwfreq *out) {
  out->e = (short) (floor(log10(in)));
  if (out->e > 8) {
    out->m = ((long) (floor(in / pow(10, out->e - 6)))) * 100;
    out->e -= 8;
  }
  else {
    out->m = in;
    out->e = 0;
  }
}

int
freq2channel(uint16_t freq) {
  if (freq >= 2412 && freq <= 2472) {
    return ((freq - 2412) / 5) + 1;
  }

  if (freq == 2484) {
    return 14;
  }

  if (freq >= 5180 && freq <= 5320) {
    return 4 * ((freq - 5180) / 20) + 36;
  }

  if (freq >= 5745 && freq <= 5809) {
    return 4 * ((freq - 5745) / 20) + 149;
  }

  return 0;
}

bool
isMonitorInterface() {
  bool d;

  pthread_mutex_lock(&ifMutex);
  d = done;
  pthread_mutex_unlock(&ifMutex);

  return !d;
}

void
stopMonitorInterface() {
  pthread_mutex_lock(&ifMutex);

  done = true;

  pthread_mutex_unlock(&ifMutex);
}

int
waitForKeyboardInput(unsigned int seconds) {
  /* File descriptor set on which to wait */
  fd_set set;
  /* Time structure which indicate the amount of time to
     wait. 0 will perform a poll */
  struct timeval timeout;

  /* Initialize the file descriptor set. */
  FD_ZERO(&set);
  /* Use the standard input as the descriptor on which to wait */
  FD_SET(STDIN_FILENO, &set);

  /* Initialize the timeout data structure. */
  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;

  /* select returns 0 if timeout, 1 if input available, -1 if error. */
  /* and is only waiting on the input selection */
  return TEMP_FAILURE_RETRY(select(FD_SETSIZE,
                            &set, NULL, NULL,
                            &timeout));
}

void
chooseNextNetwork() {
  if (isEndNetworkIterator(networkIterator)) {
    return;
  }

  nextNetwork(networkIterator);

  applyFilter();
}


/**
 * Ensure the current AP is compiant to the filter setting. If filter is true,
 * which means we are filtering out protected networks, ensure that current AP
 * is open. If it isn't find the next one that is.
 */
void
applyFilter() {
  string currentBssid;

  getNetworkIteratorBssid(networkIterator, currentBssid);

  for ( ; !isEndNetworkIterator(networkIterator);
       nextNetwork(networkIterator)) {
    if (!filter) {
      break;
    }
    else {
      string bssid;

      if (getNetworkIteratorBssid(networkIterator, bssid)) {
        NetworkInfo_t networkInfo;

        if (getNetwork(bssid, networkInfo)) {
          if (networkInfo.security & STD_OPN) {
            break;
          }
        }
      }
    }
  }

  if (!isEndNetworkIterator(networkIterator)) {
    return;
  }

  for (beginNetworkIterator(networkIterator);
       !isEndNetworkIterator(networkIterator); nextNetwork(networkIterator)) {
    string bssid;

    if (!getNetworkIteratorBssid(networkIterator, bssid)) {
      endNetworkIterator(networkIterator);
      break;
    }

    if (bssid.compare(currentBssid) == 0) {
      endNetworkIterator(networkIterator);
      break;
    }

    if (!filter) {
      break;
    }
    else {
      NetworkInfo_t networkInfo;

      if (getNetwork(bssid, networkInfo)) {
        if (networkInfo.security & STD_OPN) {
          break;
        }
      }
    }
  }
}

bool
chooseNextClient() {
  string bssid;
  int i;

  if (!getNetworkIteratorBssid(networkIterator, bssid)) {
    return false;
  }

  vector<string> clients;

  getClients(bssid, clients);

  if (currentClient.empty()) {
    // If there is no client defined, return the first client in the list
    // of clients associated with the current AP.
    if (!clients.empty()) {
      currentClient = clients.at(0);
      return true;
    }
  }


  for (i = 0; i < clients.size(); i++) {
    string client = clients.at(i);

    if (client.compare(currentClient) != 0) {
      continue;
    }

    if (i != clients.size() - 1) {
      currentClient = clients.at(i + 1);

      return true;
    }
  }

  return false;
}

void
chooseNextClientDetail() {
  clientDetailState++;
}

void
echoOff() {
  // Define a terminal configuration data structure
  struct termios term;

  // Copy the stdin terminal configuration into term
  tcgetattr(fileno(stdin), &term);

  // Turn off Canonical processing in term
  term.c_lflag &= ~ICANON;

  // Turn off screen echo in term
  term.c_lflag &= ~ECHO;

  // Set the terminal configuration for stdin according to term, now
  tcsetattr( fileno(stdin), TCSANOW, &term);
}

void
echoOn() {
  // Define a terminal configuration data structure
  struct termios term;

  // Copy the stdin terminal configuration into term
  tcgetattr(fileno(stdin), &term);

  // Turn on Canonical processing in term
  term.c_lflag |= ICANON;

  // Turn on screen echo in term
  term.c_lflag |= ECHO;

  // Set the terminal configuration for stdin according to term, now
  tcsetattr( fileno(stdin), TCSANOW, &term);
}

const char *
getSecurityString(uint32_t security) {
  if (security & STD_OPN) {
    return "OPEN";
  }
  else if (security & STD_WEP) {
    return "WEP ";
  }
  else if (security & STD_WPA) {
    return "WPA ";
  }
  else if (security & STD_WPA2) {
    return "WPA2";
  }

  return "UNKN";
}

const char *
getCommandString(Command_t command) {
  switch(command) {
  case COMMAND_NEXT:
    return "+";
  case COMMAND_BACK:
    return "-";
  case COMMAND_ZOOM_IN:
    return ">";
  case COMMAND_ZOOM_OUT:
    return "<";
  case COMMAND_FILTER_PROTECTED:
    return "F";
  case COMMAND_NO_FILTER:
    return "N";
  case COMMAND_RESET:
    return "X";
  case COMMAND_GPS:
    return "G";
  case COMMAND_WIFI:
    return "W";
  }

  return "?";
}

void
chooseNextCommand() {
  switch(currentCommand) {
  case COMMAND_NEXT:
    if (menuState == MENU_NETWORKS ||
        (menuState == MENU_NETWORK_DETAILS &&
         networkDetailState == DETAIL_NET_CLIENTS)) {
      currentCommand = COMMAND_ZOOM_IN;
    }
    else {
      currentCommand = COMMAND_ZOOM_OUT;
    }
    break;
  case COMMAND_ZOOM_IN:
    if (menuState != MENU_NETWORKS) {
      currentCommand = COMMAND_ZOOM_OUT;
      break;
    }

    if (filter) {
      currentCommand = COMMAND_NO_FILTER;
    }
    else {
      currentCommand = COMMAND_FILTER_PROTECTED;
    }
    break;
  case COMMAND_ZOOM_OUT:
    if (filter) {
      currentCommand = COMMAND_NO_FILTER;
    }
    else {
      currentCommand = COMMAND_FILTER_PROTECTED;
    }
    break;
  case COMMAND_FILTER_PROTECTED:
    currentCommand = COMMAND_RESET;
    break;
  case COMMAND_NO_FILTER:
    currentCommand = COMMAND_RESET;
    break;
  case COMMAND_RESET:
    if (menuState == MENU_GPS) {
      currentCommand = COMMAND_WIFI;
    }
    else {
      currentCommand = COMMAND_GPS;
    }
    break;
  case COMMAND_GPS:
    currentCommand = COMMAND_NEXT;
    break;
  case COMMAND_WIFI:
    currentCommand = COMMAND_RESET;
    break;
  default:
    break;
  }
}

void
chooseNextNetworkDetail() {
  networkDetailState++;

  if (networkDetailState == DETAIL_NET_CLIENTS) {
    currentClient = "";
  }
}

void
resetNetworks() {
  releaseNetworkResources();

  beginNetworkIterator(networkIterator);

  currentClient = "";
}

void
resetLocation() {
  pthread_mutex_lock(&gpsMutex);

  totalDistance = 0.0;

  startLocation.latitude = NAN;
  startLocation.longitude = NAN;
  startLocation.altitude = NAN;
  startLocation.epx = NAN;
  startLocation.epy = NAN;
  startLocation.timestamp = 0;

  pthread_mutex_unlock(&gpsMutex);
}

void
updateDistance(struct gps_fix_t *gps_fix) {
  struct timeval tv;
  char debugStr[80];

  if (gps_fix == NULL) {
    return;
  }

  if (gettimeofday(&tv, NULL) != 0) {
    return;
  }

  if (lastDistanceUpdate == 0) {
    lastDistanceUpdate = tv.tv_sec;

    return;
  }

  if (debugGps) { 
    sprintf(debugStr, "GPS reading: Altitude %lf longitude %lf\n",
            gps_fix->latitude, gps_fix->longitude);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr);
  }

  Location_t location;

  if (!isnan(gps_fix->latitude) && !isnan(gps_fix->longitude)) {
    location.latitude = gps_fix->latitude;
    location.longitude = gps_fix->longitude;
    location.altitude = gps_fix->altitude;
    distanceLocations.push_back(location);
  }

  if (distanceLocations.size() < DISTANCE_LOCATION_SAMPLES) {
    return;
  }

  lastDistanceUpdate = tv.tv_sec;

  if (isnan(lastDistanceLocation.latitude) ||
      isnan(lastDistanceLocation.longitude)) {
    getAverageLocation(location, distanceLocations);
  }
  else {
    int i;
    list<Location_t> shortest;
    list<pair<Location_t, double> > locations;

    list<Location_t>::iterator iter;
 
    for (iter = distanceLocations.begin(); iter != distanceLocations.end();
         iter++) {
      locations.push_back(
        std::make_pair(*iter,
                       getDistance(iter->latitude,
                                   lastDistanceLocation.latitude,
                                   iter->longitude,
                                   lastDistanceLocation.longitude)));
    }
   
    int num_samples =
      DISTANCE_LOCATION_SAMPLES > 3 ?
        DISTANCE_LOCATION_SAMPLES - 3 : DISTANCE_LOCATION_SAMPLES;

    for (i = 0; i < num_samples; i++) {
        double shortestDistance = 40000.0;

        list<pair<Location_t, double> >::iterator locIter;
        list<pair<Location_t, double> >::iterator shortLoc;

        for (locIter = locations.begin(); locIter != locations.end();
             locIter++) {
          if (locIter->second < shortestDistance) {
            shortLoc = locIter;
            shortestDistance = locIter->second;
          }
        }

        shortest.push_back(shortLoc->first);
        locations.erase(shortLoc);
    }

    getAverageLocation(location, shortest);
  }

  if (debugGps) {
    sprintf(debugStr, "Last average: Altitude %lf longitude %lf\n",
            lastDistanceLocation.latitude, lastDistanceLocation.longitude);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr);

    sprintf(debugStr, "Average: Altitude %lf longitude %lf (%d)\n",
            location.latitude, location.longitude, distanceLocations.size());

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr);
  }

  if (!isnan(lastDistanceLocation.latitude) && !isnan(location.latitude) &&
      !isnan(lastDistanceLocation.longitude) && !isnan(location.longitude)) {
    double distance =
      getDistance(lastDistanceLocation.latitude, lastDistanceLocation.longitude,
                  location.latitude, location.longitude);
    if (!isnan(distance)) {
      if (debugGps) {
        char debugStr[80];

        sprintf(debugStr, "Distance = %lf", distance);

        syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr);
      }
      if (distance > 0.010) {
        totalDistance += distance;
      }
    }
  }

  lastDistanceLocation.latitude = location.latitude;
  lastDistanceLocation.longitude = location.longitude;
  lastDistanceLocation.altitude = location.altitude;

  distanceLocations.clear();
}

void
getAverageLocation(Location_t& location, list<Location_t>& locations) {
    list<Location_t>::const_iterator iter;

    location.latitude = 0.0;
    location.longitude = 0.0;
    location.altitude = 0.0;

    for (iter = locations.begin(); iter != locations.end(); iter++) {
      location.latitude += iter->latitude;
      location.longitude += iter->longitude;
      location.altitude += iter->altitude;
    }

    location.latitude /= locations.size();
    location.longitude /= locations.size();
    location.altitude /= locations.size();
}

bool
isSurveyDone() {
  bool d;

  pthread_mutex_lock(&ifMutex);

  d = done;

  pthread_mutex_unlock(&ifMutex);

  return d;
}

int
getCurrentChannel() {
  int channel;

  pthread_mutex_lock(&channelMutex);

  channel = currentChannel;

  pthread_mutex_unlock(&channelMutex);

  return channel;
}
