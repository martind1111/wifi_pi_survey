#ifndef _WIFI_METADATA_H
#define _WIFI_METADATAY_H

#include <stdint.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include "WifiTypes.h"

struct WifiMetadata {
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
