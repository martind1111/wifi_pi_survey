#ifndef _WSCAN_H
#define _WSCAN_H

#include <pcap/pcap.h>
#include "gps.h"

typedef struct Location {
  double latitude;
  double longitude;
  double epx;
  double epy;
  double altitude;
  timestamp_t timestamp;
} Location_t;

typedef struct WscanContext {
  int datalink;
  char *dev;
  uint32_t npkts;
  char *oper; /* Filter or Operation */
  short int vflag; /* Verbosity flag   */
  short int eflag; /* Ethernet flag */
  FILE *out;
  pcap_t *descr;
  FILE *outPcap;
  pcap_dumper_t *dumper;
  bool interactive;
  int priority;
  bool debugLcdDisplay;
  bool debugGps;
  uint32_t activityThreshold;
} WscanContext_t;

bool isSurveyDone();

bool isMonitorInterface();

int getCurrentChannel();

void setCurrentLocation(Location_t *location);

const char *getSecurityString(uint32_t security);

#endif // _WSCAN_H
