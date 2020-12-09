#ifndef _WIFI_METADATA_H
#define _WIFI_METADATAY_H

#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include "WifiTypes.h"

struct WifiMetadata {
  WifiMetadata() : destAddrPresent(false), srcAddrPresent(false),
      bssidPresent(false), raPresent(false), taPresent(false),
      fromDs(false), toDs(false), security(0), channel(0), rate(0),
      antenna(0), txPower(0), dbNoise(0), dbSignal(0), dbSnr(0), dbmNoise(0),
      dbmSignal(0), dbmSnr(0), timestamp({0, 0}) {
      memset(&destAddr, 0, sizeof(destAddr));
      memset(&srcAddr, 0, sizeof(srcAddr));
      memset(&bssid, 0, sizeof(bssid));
      memset(&ra, 0, sizeof(ra));
      memset(&ta, 0, sizeof(ta));
      srcIpAddr.s_addr = 0;
      destIpAddr.s_addr = 0;
  }

  bool destAddrPresent;
  struct ether_addr destAddr;
  bool srcAddrPresent;
  ether_addr srcAddr;
  bool bssidPresent;
  struct ether_addr bssid;
  bool raPresent;
  ether_addr ra;
  bool taPresent;
  ether_addr ta;
  in_addr srcIpAddr;
  in_addr destIpAddr;
  char ssid[MAX_SSID_LEN + 1];
  bool fromDs;
  bool toDs;
  uint32_t security;
  uint16_t channel;
  uint16_t rate;
  uint8_t antenna;
  int8_t txPower;
  uint8_t dbNoise;
  uint8_t dbSignal;
  uint8_t dbSnr;
  int8_t dbmNoise;
  int8_t dbmSignal;
  int8_t dbmSnr;
  struct timeval timestamp;
};

#endif // _WIFI_METADATA_H
