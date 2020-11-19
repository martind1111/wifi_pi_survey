#ifndef _NETWORK_DISCOVERY_H
#define _NETWORK_DISCOVERY_H

#include <string>
#include <stdint.h>
#include <vector>
#include "gps.h"
#include <netinet/in.h>

#include "wscan.h"

#define MAX_SSID_LEN 32

using namespace std;

struct PacketSummary_t;

typedef struct ClientInfo {
  uint16_t rate;
  int8_t dbmSignal;
  int8_t dbmNoise;
  uint8_t dbSignal;
  uint8_t dbNoise;
  time_t firstSeen;
  time_t lastSeen;
  uint32_t packetCount;
  Location_t location;
} ClientInfo_t;

typedef struct NetworkInfo {
  string ssid;
  uint32_t security;
  map<string, ClientInfo_t *> clients;
  uint32_t channel;
  uint32_t radiotapChannel;
  time_t firstSeen;
  time_t lastSeen;
  uint32_t packetCount;
  Location_t location;
} NetworkInfo_t;

typedef struct NetworkIterator {
  string cursor;
  bool end;
} NetworkIterator_t;

void initNetworkDiscovery();

void beginNetworkIterator(NetworkIterator_t& networkIterator);
void endNetworkIterator(NetworkIterator_t& networkIterator);
bool isEndNetworkIterator(NetworkIterator_t& networkIterator);
bool getNetworkIteratorBssid(NetworkIterator_t& networkIterator, string& bssid);
void nextNetwork(NetworkIterator& networkIterator);

bool isOpenNetwork(WscanContext_t *context);

bool isWepNetwork(WscanContext_t *context);

bool isWpaNetwork(WscanContext_t *context);

void updateNetworkResources(WscanContext_t *context,
                            PacketSummary_t *packetSummary);

void displayNetworks(WscanContext_t *context);

bool getNetwork(const string& bssid, NetworkInfo_t& networkInfo);

bool getClient(const string& bssid, const string& clientAddr,
               ClientInfo_t& clientInfo );

void getClients(const string& bssid, vector<string>& clients);

const char *getBestClientSignal(const string& bssid);

size_t getNetworkCount();

void releaseNetworkResources();

#endif // _NETWORKK_DISCOVERY_H
