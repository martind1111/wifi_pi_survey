#ifndef _NETWORK_DISCOVERY_H
#define _NETWORK_DISCOVERY_H

#include <map>
#include <string>
#include <stdint.h>
#include <vector>
#include "gps.h"
#include <netinet/in.h>

#include "GpsTypes.h"

#define MAX_SSID_LEN 32

struct WifiMetadata;
class ApplicationContext;

typedef struct ClientInfo {
  uint16_t rate;
  int8_t dbmSignal;
  int8_t dbmNoise;
  uint8_t dbSignal;
  uint8_t dbNoise;
  time_t firstSeen;
  time_t lastSeen;
  uint32_t packetCount;
  Location location;
} ClientInfo_t;

typedef struct NetworkInfo {
  std::string ssid;
  uint32_t security;
  std::map<std::string, ClientInfo_t *> clients;
  uint32_t channel;
  uint32_t radiotapChannel;
  time_t firstSeen;
  time_t lastSeen;
  uint32_t packetCount;
  Location location;
} NetworkInfo_t;

typedef struct NetworkIterator {
  std::string cursor;
  bool end;
} NetworkIterator_t;

class NetworkDiscovery {
public:
    NetworkDiscovery(ApplicationContext* ctx) : context(ctx),
        networkMutex(PTHREAD_MUTEX_INITIALIZER) { InitNetworkDiscovery(); }

    void UpdateNetworkResources(WifiMetadata* wifiMetadata);

    void BeginNetworkIterator(NetworkIterator_t& networkIterator);
    void EndNetworkIterator(NetworkIterator_t& networkIterator);
    bool IsEndNetworkIterator(NetworkIterator_t& networkIterator);
    bool GetNetworkIteratorBssid(NetworkIterator_t& networkIterator,
                                 std::string& bssid);
    void NextNetwork(NetworkIterator& networkIterator);

    struct ether_addr *GetBssid(WifiMetadata* wifiMetadata);
    bool IsNetworkAddress(struct ether_addr* macAddr);
    bool IsClientAddress(struct ether_addr* addr);
    bool IsSecureNetwork(int securityMask);
    bool IsOpenNetwork(const ApplicationContext* context);
    bool IsWepNetwork(const ApplicationContext* context);
    bool IsWpaNetwork(const ApplicationContext* context);

    void DisplayNetworks(ApplicationContext* context);

    bool GetNetwork(const std::string& bssid, NetworkInfo_t& networkInfo);
    bool GetClient(const std::string& bssid, const std::string& clientAddr,
                   ClientInfo_t& clientInfo );
    void GetClients(const std::string& bssid,
                    std::vector<std::string>& clients);
    const char *GetBestClientSignal(const std::string& bssid);
    size_t GetNetworkCount();

    void ReleaseNetworkResources();

private:
    void InitNetworkDiscovery();

    void ReportNetwork(struct ether_addr* bssid,
                       WifiMetadata* wifiMetadata);
    void ReportClient(struct ether_addr* bssid,
                      struct ether_addr* client, WifiMetadata* wifiMetadata);
    void ReportUnassignedClient(struct ether_addr* client,
                                WifiMetadata* wifiMetadata);

    ApplicationContext* context;

    NetworkIterator_t networkIterator;

    std::map<std::string, NetworkInfo_t*> networks;

    std::map<std::string, string> assignedClients;

    std::map<std::string, ClientInfo_t*> unassignedClients;

    pthread_mutex_t networkMutex;
};

#endif // _NETWORKK_DISCOVERY_H
