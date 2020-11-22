#include <map>
#include <bits/stl_pair.h>
#include <pthread.h>
#include <netinet/ether.h>
#include <math.h>
#include <string.h>
#include <sstream>
#include <syslog.h>

#include "networkDiscovery.h"
#include "airodump-ng.h"
#include "manufacturer.h"

#include "GpsTypes.h"
#include "WifiMetadata.h"
#include "Application.h"

using namespace std;

static struct ether_addr BROADCAST_ADDRESS;
static struct ether_addr MULTICAST_ADDRESS;
static struct ether_addr MULTICAST_IPV6_ADDRESS;

namespace {
void InitReservedAddresses();
int compare_ether_addr(struct ether_addr* eaddr,
                       struct ether_addr* baseAddr, uint32_t numBytes);
bool IsBroadcast(struct ether_addr* eaddr);
bool IsMulticast(struct ether_addr* eaddr);
bool IsIpv6Multicast(struct ether_addr* eaddr);
uint32_t GetElapsed(time_t t);
void SetCurrentLocation(Location* location, ApplicationContext* context);
}

void
NetworkDiscovery::InitNetworkDiscovery() {
  InitReservedAddresses();
}

namespace {
void
InitReservedAddresses() {
  uint8_t broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  memcpy(BROADCAST_ADDRESS.ether_addr_octet, broadcast, ETH_ALEN);
  uint8_t multicast[ETH_ALEN] =  { 0x01, 0x00, 0x5e, 0, 0, 0 };
  memcpy(MULTICAST_ADDRESS.ether_addr_octet, multicast, ETH_ALEN);
  uint8_t multicastIpv6[ETH_ALEN] = { 0x33, 0x33, 0, 0, 0, 0 };
  memcpy(MULTICAST_IPV6_ADDRESS.ether_addr_octet, multicastIpv6, ETH_ALEN);
}
} // namespace

void
NetworkDiscovery::UpdateNetworkResources(WifiMetadata* wifiMetadata) {
  struct ether_addr* bssid = getBssid(wifiMetadata);

  if (bssid != NULL) {
    ReportNetwork(bssid, wifiMetadata);

    if (wifiMetadata->srcAddrPresent &&
        IsClientAddress(&wifiMetadata->srcAddr)) {
      ReportClient(bssid, &wifiMetadata->srcAddr, wifiMetadata);
    }

    if (wifiMetadata->destAddrPresent &&
        IsClientAddress(&wifiMetadata->destAddr)) {
      ReportClient(bssid, &wifiMetadata->destAddr, wifiMetadata);
    }

    if (wifiMetadata->raPresent && IsClientAddress(&wifiMetadata->ra)) {
      ReportClient(bssid, &wifiMetadata->ra, wifiMetadata);
    }

    if (wifiMetadata->taPresent && IsClientAddress(&wifiMetadata->ta)) {
      ReportClient(this->context, bssid, &wifiMetadata->ta, wifiMetadata);
    }
  }
  else {
    if (wifiMetadata->srcAddrPresent &&
        IsClientAddress(&wifiMetadata->srcAddr)) {
      ReportUnassignedClient(&wifiMetadata->srcAddr, wifiMetadata);
    }

    if (wifiMetadata->destAddrPresent &&
        IsClientAddress(&wifiMetadata->destAddr)) {
      ReportUnassignedClient(&wifiMetadata->destAddr, wifiMetadata);
    }

    if (wifiMetadata->raPresent && IsClientAddress(&wifiMetadata->ra)) {
      ReportUnassignedClient(&wifiMetadata->ra, wifiMetadata);
    }

    if (wifiMetadata->taPresent && IsClientAddress(&wifiMetadata->ta)) {
      ReportUnassignedClient(&wifiMetadata->ta, wifiMetadata);
    }
  }
}

void
NetworkDiscovery::ReportNetwork(struct ether_addr* bssid,
                                WifiMetadata* wifiMetadata) {
  map<string, NetworkInfo_t*>::iterator iter;
  NetworkInfo_t* networkInfo;

  if (isBroadcast(bssid)) {
    return;
  }

  string eaddr = string(ether_ntoa(bssid));

  pthread_mutex_lock(&networkMutex);

  iter = networks.find(eaddr);

  bool found = iter != networks.end();

  pthread_mutex_unlock(&networkMutex);

  if (!found) {
    networkInfo = new NetworkInfo_t();

    if (wifiMetadata->ssid[0] != '\0') {
      networkInfo->ssid = wifiMetadata->ssid;
    }

    networkInfo->security = wifiMetadata->security;

    networkInfo->channel = getCurrentChannel();

    networkInfo->radiotapChannel = freq2channel(wifiMetadata->channel);

    networkInfo->firstSeen = wifiMetadata->timestamp.tv_sec;

    networkInfo->lastSeen = wifiMetadata->timestamp.tv_sec;

    networkInfo->packetCount = 1;

    if (wifiMetadata->channel != 0) {
      networkInfo->radiotapChannel = freq2channel(wifiMetadata->channel);
    }

    SetCurrentLocation(&networkInfo->location, this->context);

    pthread_mutex_lock(&networkMutex);

    networks[eaddr] = networkInfo;

    pthread_mutex_unlock(&networkMutex);

    ostringstream ostr;

    ostr << "Added network " << eaddr;

    if (!networkInfo->ssid.empty()) {
      ostr << " (SSID " << networkInfo->ssid
           << ")";
    }

    syslog(this->context->priority, ostr.str().c_str());

    return;
  }

  string ssid;

  pthread_mutex_lock(&networkMutex);

  if (iter->second->ssid.empty()) {
    ssid = string(wifiMetadata->ssid);
    iter->second->ssid = ssid;
  }

  iter->second->channel = getCurrentChannel();

  if (wifiMetadata->channel != 0) {
    iter->second->radiotapChannel = freq2channel(wifiMetadata->channel);
  }

  if (wifiMetadata->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)) {
    iter->second->security = wifiMetadata->security;
  }

  iter->second->lastSeen = wifiMetadata->timestamp.tv_sec;

  iter->second->packetCount++;

  if (wifiMetadata->channel != 0) {
    iter->second->radiotapChannel = freq2channel(wifiMetadata->channel);
  }

  SetCurrentLocation(&iter->second->location);

  pthread_mutex_unlock(&networkMutex);

  if (!ssid.empty()) {
    ostringstream ostr;

    ostr << "Detected SSID " << ssid << " for BSSID " << eaddr;

    syslog(this->context->priority, ostr.str().c_str());
  }
}

void
NetworkDiscovery::ReportClient(struct ether_addr* bssid,
                               struct ether_addr* client,
                               WifiMetadata* wifiMetadata) {
  map<string, NetworkInfo*>::iterator iter;
  string bssidStr = string(ether_ntoa(bssid));
  string clientAddr = string(ether_ntoa(client));
  map<string, ClientInfo_t*>::iterator clientIter;
  bool newClient = false;
  string ssid;

  pthread_mutex_lock(&networkMutex);

  iter = networks.find(bssidStr);

  if (iter == networks.end()) {
    // BSSID isn't part of the network table: Ignore it.
    pthread_mutex_unlock(&networkMutex);

    return;
  }

  NetworkInfo_t* network = iter->second;

  clientIter = network->clients.find(clientAddr);

  if (clientIter == network->clients.end()) {
    ClientInfo* clientInfo = new ClientInfo_t();

    clientInfo->firstSeen = wifiMetadata->timestamp.tv_sec;
    clientInfo->lastSeen = wifiMetadata->timestamp.tv_sec;
    clientInfo->packetCount = 1;
    if (wifiMetadata->rate != 0) {
      clientInfo->rate = wifiMetadata->rate;
    }
    if (wifiMetadata->dbmSignal != 0) {
      clientInfo->dbmSignal = wifiMetadata->dbmSignal;
    }
    else {
      clientInfo->dbmSignal = 0;
    }
    if (wifiMetadata->dbmNoise != 0) {
      clientInfo->dbmNoise = wifiMetadata->dbmNoise;
    }
    else {
      clientInfo->dbmNoise = 0;
    }

    network->clients.insert(make_pair(clientAddr, clientInfo));

    assignedClients.insert(make_pair(clientAddr, bssidStr));

    newClient = true;
    ssid = network->ssid;
  }
  else {
    clientIter->second->lastSeen = wifiMetadata->timestamp.tv_sec;
    clientIter->second->packetCount++;
    if (wifiMetadata->rate != 0) {
      clientIter->second->rate = wifiMetadata->rate;
    }
    if (wifiMetadata->dbmSignal != 0) {
      clientIter->second->dbmSignal = wifiMetadata->dbmSignal;
    }
    if (wifiMetadata->dbmNoise != 0) {
      clientIter->second->dbmNoise = wifiMetadata->dbmNoise;
    }
  }

  // Remove BSSID and client addresses from unassigned clients.
  clientIter = unassignedClients.find(bssidStr);

  if (clientIter != unassignedClients.end()) {
    unassignedClients.erase(clientIter);
  }

  clientIter = unassignedClients.find(clientAddr);

  if (clientIter != unassignedClients.end()) {
    unassignedClients.erase(clientIter);
  }

  pthread_mutex_unlock(&networkMutex);

  if (newClient) {
    ostringstream ostr;

    ostr << "Added client " << clientAddr << " to BSSID " << bssid;

    if (!ssid.empty()) {
      ostr << " (SSID " << ssid << ")";
    }

    syslog(this->context->priority, ostr.str().c_str());
  }
}

void
NetworkDiscovery::ReportUnassignedClient(struct ether_addr* client,
                                         WifiMetadata* wifiMetadata) {
  map<string, string>::iterator iter;
  string clientAddr = string(ether_ntoa(client));

  // Add client to unassigned clients if not already assigned.
  iter = assignedClients.find(clientAddr);

  if (iter != assignedClients.end()) {
    struct ether_addr *bssid = ether_aton(iter->second.c_str());
    reportClient(this->context, bssid, client, wifiMetadata);

    return;
  }

  map<string, ClientInfo_t *>::iterator clientIter;

  clientIter = unassignedClients.find(clientAddr);

  if (clientIter == unassignedClients.end()) {
    ClientInfo_t *clientInfo = new ClientInfo_t();

    clientInfo->lastSeen = wifiMetadata->timestamp.tv_sec;
    clientInfo->packetCount = 1;
    unassignedClients.insert(make_pair(clientAddr, clientInfo));
  }
  else {
    clientIter->second->lastSeen = wifiMetadata->timestamp.tv_sec;
    clientIter->second->packetCount++;
  }
}

/**
 * Determine if the specified MAC address has been flagged as a BSSID.
 */
static bool
NetworkDiscovery::IsNetworkAddress(struct ether_addr* macAddr) {
  return networks.find(ether_ntoa(macAddr)) != networks.end();
}

static bool
NetworkDiscovery::IsClientAddress(struct ether_addr* addr) {
  return !IsNetworkAddress(addr) && !IsBroadcast(addr) && !IsMulticast(addr);
}

struct ether_addr*
NetworkDiscovery::GetBssid(WifiMetadata* wifiMetadata) {
  string bssid;
  string srcAddr;
  string destAddr;
  string ra;
  string ta;
  string clientAddr;

  if (wifiMetadata->bssidPresent && !isBroadcast(&wifiMetadata->bssid) &&
      !isMulticast(&wifiMetadata->bssid)) {
    return &wifiMetadata->bssid;
  }

  if (wifiMetadata->srcAddrPresent &&
      IsNetworkAddress(&wifiMetadata->srcAddr)) {
    return &wifiMetadata->srcAddr;
  }

  if (wifiMetadata->destAddrPresent &&
      IsNetworkAddress(&wifiMetadata->destAddr)) {
    return &wifiMetadata->destAddr;
  }

  if (wifiMetadata->raPresent && IsNetworkAddress(&wifiMetadata->ra)) {
    return &wifiMetadata->ra;
  }

  if (wifiMetadata->taPresent && IsNetworkAddress(&wifiMetadata->ta)) {
    return &wifiMetadata->ta;
  }

  return NULL;
}

bool
NetworkDiscovery::GetClient(const string& bssid, const string& clientAddr,
          ClientInfo_t& clientInfo) {
  map<string, NetworkInfo_t *>::iterator iter;
  bool found = false;

  pthread_mutex_lock(&networkMutex);

  iter = networks.find(bssid);

  if (iter != networks.end()) {
    map<string, ClientInfo_t *>::iterator clientIter;
    NetworkInfo_t *networkInfo;

    networkInfo = iter->second;

    clientIter = networkInfo->clients.find(clientAddr);

    if (clientIter != networkInfo->clients.end()) {
      found = true;
      clientInfo.firstSeen = clientIter->second->firstSeen;
      clientInfo.lastSeen = clientIter->second->lastSeen;
      clientInfo.packetCount = clientIter->second->packetCount;
      clientInfo.dbmSignal = clientIter->second->dbmSignal;
      clientInfo.dbmNoise = clientIter->second->dbmNoise;
      clientInfo.dbSignal = clientIter->second->dbSignal;
      clientInfo.dbNoise = clientIter->second->dbNoise;
      clientInfo.rate = clientIter->second->rate;
      clientInfo.location = clientIter->second->location;
    }
    else {
      clientInfo.firstSeen = 0;
      clientInfo.lastSeen = 0;
      clientInfo.packetCount = 0;
      clientInfo.dbmSignal = 0;
      clientInfo.dbmNoise = 0;
      clientInfo.dbSignal = 0;
      clientInfo.dbNoise = 0;
      clientInfo.rate = 0;
      clientInfo.location.latitude = NAN;
      clientInfo.location.longitude = NAN;
      clientInfo.location.altitude = NAN;
      clientInfo.location.timestamp = 0;
    }
  }

  pthread_mutex_unlock(&networkMutex);

  return true;
}

static bool
NetworkDiscovery::IsSecureNetwork(int securityMask) {
  map<string, NetworkInfo_t*>::iterator iter;
  bool secureNetwork = false;

  pthread_mutex_lock(&networkMutex);

  for (iter = networks.begin(); iter != networks.end(); iter++) {
    NetworkInfo_t* networkInfo = iter->second;

    if (networkInfo->security & securityMask) {
      if (GetElapsed(networkInfo->lastSeen) <=
          this->context->activityThreshold) {
        secureNetwork = true;
     
        break;
      }
    }
  }

  pthread_mutex_unlock(&networkMutex);

  return secureNetwork;
}

bool
NetworkDiscovery::IsOpenNetwork(const ApplicationContext* context) {
  return IsSecureNetwork(context, STD_OPN);
}

bool
NetworkDiscovery::IsWepNetwork(const ApplicationContext* context) {
  return IsSecureNetwork(context, STD_WEP);
}

bool
NetworkDiscovery::IsWpaNetwork(const ApplicationContext* context) {
  return IsSecureNetwork(context, STD_WPA) ||
    IsSecureNetwork(context, STD_WPA2);
}

void
NetworkDiscovery::BeginNetworkIterator(NetworkIterator_t& networkIterator) {
  pthread_mutex_lock(&networkMutex);

  map<string, NetworkInfo_t *>::const_iterator iter;

  iter = networks.begin();

  if (iter == networks.end()) {
    networkIterator.cursor = "";
    networkIterator.end = true;
  }
  else {
    networkIterator.cursor = iter->first; 
    networkIterator.end = false;
  }

  pthread_mutex_unlock(&networkMutex);
}

void
NetworkDiscovery::EndNetworkIterator(NetworkIterator_t& networkIterator) {
  networkIterator.cursor = "";
  networkIterator.end = true;
}

bool
NetworkDiscovery::IsEndNetworkIterator(NetworkIterator_t& networkIterator) {
  return networkIterator.end;
}

bool
NetworkDiscovery::GetNetworkIteratorBssid(NetworkIterator_t& networkIterator,
                                          string& bssid) {
  if (networkIterator.end) {
    return false;
  }

  bssid = networkIterator.cursor;

  return true;
}

void
NetworkDiscovery::NextNetwork(NetworkIterator_t& networkIterator) {
  map<string, NetworkInfo_t *>::const_iterator iter;

  pthread_mutex_lock(&networkMutex);

  iter = networks.find(networkIterator.cursor);

  if (iter != networks.end()) {
    iter++;

    if (iter != networks.end()) {
      networkIterator.cursor = iter->first;
      networkIterator.end = false;
    }
    else {
      networkIterator.cursor = "";
      networkIterator.end = true;
    }
  }

  pthread_mutex_unlock(&networkMutex);
}

void
NetworkDiscovery::DisplayNetworks() {
  map<string, NetworkInfo_t*>::const_iterator iter;
  map<string, ClientInfo_t*>::const_iterator clientIter;

  fprintf(this->context->out, "Networks:\n");

  for (iter = networks.begin(); iter != networks.end(); iter++) {
    fprintf(this->context->out, "BSSID: %s ", iter->first.c_str());

    if (!iter->second->ssid.empty()) {
      fprintf(this->context->out, "SSID: %s ", iter->second->ssid.c_str());
    }

    if (iter->second->radiotapChannel != 0) {
      fprintf(this->context->out, "channel %d ", iter->second->radiotapChannel);
    }
    else if (iter->second->channel != 0) {
      fprintf(this->context->out, "channel %d* ", iter->second->channel);
    }

    fprintf(this->context->out, "privacy %s ",
            getSecurityString(iter->second->security));
    double latitude = iter->second->location.latitude;
    double longitude = iter->second->location.longitude;

    if (!isnan(latitude)) {
      fprintf(this->context->out, "latitude = %lf, ", latitude);
    }

    if (!isnan(longitude)) {
      fprintf(this->context->out, "longitude = %lf, ", longitude);
    }

    fprintf(this->context->out, "\n");

    for (clientIter = iter->second->clients.begin();
         clientIter != iter->second->clients.end(); clientIter++) {
      struct ether_addr *addr = ether_aton(clientIter->first.c_str());
      const char *manuf = getManufacturer(addr);
      fprintf(this->context->out, "  %s ", clientIter->first.c_str());
      if (manuf != NULL) {
        fprintf(this->context->out, "%s", manuf);
      }

      fprintf(this->context->out, "\n");
      int rate = clientIter->second->rate;
      if (rate != 0) {
        fprintf(this->context->out, "    Rate (Mbps): %d\n", rate / 10);
      }
      int signal = clientIter->second->dbmSignal;
      if (signal != 0) {
        fprintf(this->context->out, "    Signal (dbm): %d\n", signal);
      }
      int noise = clientIter->second->dbmNoise;
      if (noise != 0) {
        fprintf(this->context->out, "    Noise (dbm): %d\n", noise);
      }
      if (clientIter->second->firstSeen != 0) {
        struct tm *brokenDownTime = gmtime(&clientIter->second->firstSeen);
        fprintf(this->context->out,
                "    First seen: %04d-%02d-%02d %02d:%02d:%02d\n",
                brokenDownTime->tm_year + 1900, brokenDownTime->tm_mon + 1,
                brokenDownTime->tm_mday, brokenDownTime->tm_hour,
                brokenDownTime->tm_min, brokenDownTime->tm_sec);
      }
      if (clientIter->second->lastSeen != 0) {
        struct tm *brokenDownTime = gmtime(&clientIter->second->lastSeen);
        fprintf(this->context->out,
                "    Last seen: %04d-%02d-%02d %02d:%02d:%02d\n",
                brokenDownTime->tm_year + 1900, brokenDownTime->tm_mon + 1,
                brokenDownTime->tm_mday, brokenDownTime->tm_hour,
                brokenDownTime->tm_min, brokenDownTime->tm_sec);
      }
      fprintf(this->context->out, "    Packets: %d\n",
              clientIter->second->packetCount);
    }
  }

  fprintf(this->context->out, "Unassigned clients:\n");

  for (clientIter = unassignedClients.begin();
       clientIter != unassignedClients.end(); clientIter++) {
    struct ether_addr *addr = ether_aton(clientIter->first.c_str());
    const char *manuf = getManufacturer(addr);
    fprintf(this->context->out, "  %s %s\n", clientIter->first.c_str(),
            manuf == NULL ? "" : manuf);
  }
}

bool
NetworkDiscovery::GetNetwork(const string& bssid, NetworkInfo_t& networkInfo) {
  bool found = false;

  pthread_mutex_lock(&networkMutex);

  map<string, NetworkInfo *>::const_iterator iter;

  iter = networks.find(bssid);

  if (iter != networks.end()) {
    networkInfo.ssid = iter->second->ssid;
    networkInfo.security = iter->second->security;
    networkInfo.channel = iter->second->channel;
    networkInfo.radiotapChannel = iter->second->radiotapChannel;
    networkInfo.firstSeen = iter->second->firstSeen;
    networkInfo.lastSeen = iter->second->lastSeen;
    networkInfo.packetCount = iter->second->packetCount;
    networkInfo.location = iter->second->location;
    found = true;
  }
  else {
    networkInfo.ssid = "";
    networkInfo.security = 0;
    networkInfo.channel = 0;
    networkInfo.radiotapChannel = 0;
    networkInfo.firstSeen = 0;
    networkInfo.lastSeen = 0;
    networkInfo.packetCount = 0;
    networkInfo.location.latitude = 0;
    networkInfo.location.longitude = 0;
    networkInfo.location.altitude = 0;
    networkInfo.location.timestamp = 0;
  }

  pthread_mutex_unlock(&networkMutex);

  return found;
}

size_t
NetworkDiscovery::GetNetworkCount() {
  size_t networkCount;

  pthread_mutex_lock(&networkMutex);

  networkCount = networks.size();

  pthread_mutex_unlock(&networkMutex);

  return networkCount;
}

void
NetworkDiscovery::ReleaseNetworkResources() {
  map<string, NetworkInfo_t *>::iterator iter;
  map<string, NetworkInfo_t *>::iterator del;
  map<string, ClientInfo_t *>::iterator clientIter;
  map<string, ClientInfo_t *>::iterator delClient;

  pthread_mutex_lock(&networkMutex);

  for (iter = networks.begin(); iter != networks.end(); ) {
    NetworkInfo_t *network = iter->second;

    for (clientIter = network->clients.begin();
         clientIter != network->clients.end(); ) {
      ClientInfo_t *client = clientIter->second;

      delete client;

      delClient = clientIter;

      clientIter++;

      network->clients.erase(delClient);
    }

    delete network;

    del = iter;

    iter++;

    networks.erase(del);
  }

  for (clientIter = unassignedClients.begin();
       clientIter != unassignedClients.end(); ) {
    ClientInfo_t *client = clientIter->second;

    delete client;

    delClient = clientIter;

    clientIter++;

    unassignedClients.erase(delClient);
  }

  pthread_mutex_unlock(&networkMutex);
}

const char *
NetworkDiscovery::GetBestClientSignal(const string& bssid) {
  map<string, NetworkInfo_t *>::iterator iter;

  pthread_mutex_lock(&networkMutex);

  iter = networks.find(bssid);

  int bestSignal = -128;

  if (iter != networks.end()) {
    map<string, ClientInfo_t *>::iterator clientIter;

    for (clientIter = iter->second->clients.begin();
         clientIter != iter->second->clients.end(); clientIter++) {
      if (clientIter->second->dbmSignal > bestSignal) {
        bestSignal = clientIter->second->dbmSignal;
      }
    }
  }

  pthread_mutex_unlock(&networkMutex);

  if (bestSignal == -128) {
    return NULL;
  }

  if (bestSignal > -40) {
    return "5/5";
  }
  else if (bestSignal > -50) {
    return "4/5";
  }
  if (bestSignal > -60) {
    return "3/5";
  }
  if (bestSignal > -70) {
    return "2/5";
  }

  return "1/5";
}

void
NetworkDiscovery::GetClients(const string& bssid, vector<string>& clients) {
  map<string, NetworkInfo_t*>::const_iterator iter;

  pthread_mutex_lock(&networkMutex);

  iter = networks.find(bssid);

  if (iter != networks.end()) {
    map<string, ClientInfo_t*>::const_iterator clientIter;

    clients.clear();

    for (clientIter = iter->second->clients.begin();
         clientIter != iter->second->clients.end(); clientIter++) {
      clients.push_back(clientIter->first);
    }
  }

  pthread_mutex_unlock(&networkMutex);
}

namespace {
int
compare_ether_addr(struct ether_addr* eaddr, struct ether_addr* baseAddr,
                   uint32_t numBytes) {
  int i;

  for (i = 0; i < numBytes; i++) {
    int diff = eaddr->ether_addr_octet[i] - baseAddr->ether_addr_octet[i];

    if (diff != 0) {
      return diff;
    }
  }

  return 0;
}

bool
IsBroadcast(struct ether_addr* eaddr) {
  return compare_ether_addr(eaddr, &BROADCAST_ADDRESS, ETH_ALEN) == 0;
}

bool
IsMulticast(struct ether_addr* eaddr) {
  return compare_ether_addr(eaddr, &MULTICAST_ADDRESS, 3) == 0 ||
    IsIpv6Multicast(eaddr);
}

bool
IsIpv6Multicast(struct ether_addr* eaddr) {
  return compare_ether_addr(eaddr, &MULTICAST_IPV6_ADDRESS, 2) == 0;
}

uint32_t GetElapsed(time_t t) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) == -1) {
    return 0;
  }

  if (t > tv.tv_sec) {
    return 0;
  }

  return (uint32_t) (tv.tv_sec - t);  
}

void
SetCurrentLocation(Location* location, ApplicationContext* context) {
  location->latitude = context->lastLocation.latitude;

  location->longitude = context->lastLocation.longitude;

  location->altitude = context->lastLocation.altitude;

  location->epx = context->lastLocation.epx;

  location->epy = context->lastLocation.epy;

  location->timestamp = context->lastLocation.timestamp;
}
}
