#ifndef _APPLICATION_H
#define _APPLICATION_H

#include <pcap/pcap.h>
#include "gps.h"

#include "GpsTypes.h"
#include "HeartbeatTypes.h"

class HeartbeatMonitor;
class GpsMonitor;
class NetworkDiscovery;
struct NetworkIterator_t;

class Application {
public:
    bool IsShuttingDown() const;
    void Shutdown();
    void LogError(int opmode, const char* module, const char* message) const;
};

class ApplicationContext {
public:
  ApplicationContext(Application* app) : application(app), opmode(0),
    heartbeatMonitor(nullptr), gpsMonitor(nullptr) { }
  Application* GetApplication() const { return application; }
  void ReportActivity(const Activity_t activity);
  void ResetLocation();
  void SetHeartbeatMonitor(HeartbeatMonitor* monitor) {
    heartbeatMonitor = monitor;
  }
  void SetGpsMonitor(GpsMonitor* monitor) { gpsMonitor = monitor; }
  void SetNetworkDiscovery(NetworkDiscovery* netDiscovery) {
      networkDiscovery = netDiscovery;
  }
  NetworkIterator_t* GetNetworkIterator();

  int datalink;
  char* dev;
  uint32_t npkts;
  char* oper; /* Filter or Operation */
  short int vflag; /* Verbosity flag   */
  short int eflag; /* Ethernet flag */
  FILE* out;
  pcap_t* descr;
  FILE* outPcap;
  pcap_dumper_t* dumper;
  bool interactive;
  int priority;
  Location lastLocation;
  double totalDistance;
  bool debugLcdDisplay;
  bool debugGps;
  uint32_t activityThreshold;
  int opmode;

private:
  Application* application;
  HeartbeatMonitor* heartbeatMonitor;
  GpsMonitor* gpsMonitor;
  NetworkDiscovery* networkDiscovery;
};

#endif // _APPLICATION_H
