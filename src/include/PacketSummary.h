#ifndef _PACKET_SUMMARY_H
#define _PACKET_SUMMARY_H

#include <stdint.h>

struct PacketSummary_t {
  bool destAddrPresent;
  struct ether_addr destAddr;
  bool srcAddrPresent;
  struct ether_addr srcAddr;
  bool bssidPresent;
  struct ether_addr bssid;
  bool raPresent;
  struct ether_addr ra;
  bool taPresent;
  struct ether_addr ta;
  struct in_addr srcIpAddr;
  struct in_addr destIpAddr;
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

#endif // _PACKET_SUMMARY_H
