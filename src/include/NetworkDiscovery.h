#ifndef _NETWORK_DISCOVERY_H
#define _NETWORK_DISCOVERY_H

#include <map>
#include <string>
#include <stdint.h>
#include <vector>
#include "gps.h"
#include <netinet/in.h>

#include "GpsTypes.h"
#include "WifiTypes.h"

struct WifiMetadata;
class ApplicationContext;
struct ether_addr;

struct ClientInfo {
  ClientInfo() : rate(0), dbmSignal(0), dbmNoise(0), dbSignal(0), dbNoise(0),
    firstSeen(0), lastSeen(0), packetCount(0) {}
  uint16_t rate;
  int8_t dbmSignal;
  int8_t dbmNoise;
  uint8_t dbSignal;
  uint8_t dbNoise;
  time_t firstSeen;
  time_t lastSeen;
  uint32_t packetCount;
  Location location;
};

struct NetworkInfo {
  NetworkInfo() : security(0), channel(0), radiotapChannel(0), firstSeen(0),
    lastSeen(0), packetCount(0) {}
  std::string ssid;
  uint32_t security;
  std::map<std::string, ClientInfo*> clients;
  uint32_t channel;
  uint32_t radiotapChannel;
  time_t firstSeen;
  time_t lastSeen;
  uint32_t packetCount;
  Location location;
};

struct NetworkIterator {
  std::string cursor;
  bool end;
};

class NetworkDiscovery {
public:
    NetworkDiscovery(ApplicationContext* ctx) : context(ctx),
        networkMutex(PTHREAD_MUTEX_INITIALIZER) { InitNetworkDiscovery(); }

    void UpdateNetworkResources(const WifiMetadata* wifiMetadata);

    void BeginNetworkIterator(NetworkIterator& networkIterator);
    void EndNetworkIterator(NetworkIterator& networkIterator);
    bool IsEndNetworkIterator(NetworkIterator& networkIterator);
    bool GetNetworkIteratorBssid(NetworkIterator& networkIterator,
                                 std::string& bssid);
    void NextNetwork(NetworkIterator& networkIterator);

    void DisplayNetworks();

    bool IsNetworkAddress(const ether_addr* macAddr);
    bool IsClientAddress(const ether_addr* addr);
    bool IsSecureNetwork(int securityMask);
    bool IsOpenNetwork();
    bool IsWepNetwork();
    bool IsWpaNetwork();

    bool GetNetwork(const std::string& bssid, NetworkInfo& networkInfo);
    const ether_addr *GetBssid(const WifiMetadata* wifiMetadata);
    bool GetClient(const std::string& bssid, const std::string& clientAddr,
                   ClientInfo& clientInfo);
    void GetClients(const std::string& bssid,
                    std::vector<std::string>& clients);
    uint32_t GetSecurity(const ether_addr* bssid);
    const char *GetBestClientSignal(const std::string& bssid);
    size_t GetNetworkCount();

    void ReleaseNetworkResources();

private:
    void InitNetworkDiscovery();

    void ReportNetwork(const ether_addr* bssid,
                       const WifiMetadata* wifiMetadata);
    void ReportClient(const ether_addr* bssid,
                      const ether_addr* client,
                      const WifiMetadata* wifiMetadata);
    void ReportUnassignedClient(const ether_addr* client,
                                const WifiMetadata* wifiMetadata);

    ApplicationContext* context;

    NetworkIterator networkIterator;

    std::map<std::string, NetworkInfo*> networks;

    std::map<std::string, std::string> assignedClients;

    std::map<std::string, ClientInfo*> unassignedClients;

    pthread_mutex_t networkMutex;
};

#endif // _NETWORK_DISCOVERY_H
