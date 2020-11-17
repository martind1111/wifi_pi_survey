#include <map>
#include <sstream>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <stdint.h>

#include "heartbeat.h"
#include "wscan.h"

using namespace std;

pthread_mutex_t threadStatusMutex = PTHREAD_MUTEX_INITIALIZER;

static void logThreadStatus(WscanContext_t *context);

map<Activity_t, bool> threadStatus;

void
reportActivity(const Activity_t activity) {
  pthread_mutex_lock(&threadStatusMutex);

  map<Activity_t, bool>::iterator iter = threadStatus.find(activity);

  if (iter != threadStatus.end()) {
    iter->second = true;
  }

  pthread_mutex_unlock(&threadStatusMutex);
}

static void
logThreadStatus(WscanContext_t *context) {
  bool monitorInterfaceStatus = false;
  bool monitorGpsStatus = false;
  bool scanChannelStatus = false;
  bool displayMenuStatus = false;
  bool journalDbStatus = false;

  map<Activity_t, bool>::iterator iter;

  pthread_mutex_lock(&threadStatusMutex);

  iter = threadStatus.find(ACTIVITY_MONITOR_INTERFACE);

  if (iter != threadStatus.end()) {
    monitorInterfaceStatus = iter->second;
    iter->second = false;
  }

  iter = threadStatus.find(ACTIVITY_MONITOR_GPS);

  if (iter != threadStatus.end()) {
    monitorGpsStatus = iter->second;
    iter->second = false;
  }

  iter = threadStatus.find(ACTIVITY_SCAN_CHANNEL);

  if (iter != threadStatus.end()) {
    scanChannelStatus = iter->second;
    iter->second = false;
  }

  iter = threadStatus.find(ACTIVITY_DISPLAY_MENU);

  if (iter != threadStatus.end()) {
    displayMenuStatus = iter->second;
    iter->second = false;
  }

  iter = threadStatus.find(ACTIVITY_JOURNAL_DB);

  if (iter != threadStatus.end()) {
    journalDbStatus = iter->second;
    iter->second = false;
  }

  pthread_mutex_unlock(&threadStatusMutex);

  ostringstream ostr;

  ostr << "Thread status:"
          " Monitor interface " << monitorInterfaceStatus
       << ", Monitor GPS " << monitorGpsStatus
       << ", Scan channels " << scanChannelStatus
       << ", Display menu " << displayMenuStatus
       << ", Journal DB " << journalDbStatus;

  syslog(context->priority, "%s", ostr.str().c_str());
}

void *
monitorHeartbeat(void *context) {
  WscanContext_t *wscanContext = (WscanContext_t *) context;
  Activity_t i;

  for (i = ACTIVITY_MONITOR_INTERFACE; i != ACTIVITY_LAST; i++) {
    threadStatus[i] = false;
  }

  for ( ; ; ) {
    if (!isMonitorInterface()) {
      break;
    }

    sleep(60);

    logThreadStatus(wscanContext);
  }

  return NULL;
}

