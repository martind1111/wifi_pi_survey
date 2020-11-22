#include <map>
#include <sstream>
#include <syslog.h>
#include <unistd.h>
#include <stdint.h>

#include "HeartbeatMonitor.h"
#include "Application.h"

using namespace std;

void*
MonitorHeartbeat(void* ctx) {
    ApplicationContext* context = reinterpret_cast<ApplicationContext*>(ctx);
    HeartbeatMonitor monitor(context);

    context->SetHeartbeatMonitor(&monitor);

    monitor.Run();

    return nullptr;
}

void
HeartbeatMonitor::ReportActivity(const Activity_t activity) {
  pthread_mutex_lock(&threadStatusMutex);

  std::map<Activity_t, bool>::iterator iter = threadStatus.find(activity);

  if (iter != threadStatus.end()) {
    iter->second = true;
  }

  pthread_mutex_unlock(&threadStatusMutex);
}

void
HeartbeatMonitor::Run() {
  Activity_t i;

  for (i = ACTIVITY_MONITOR_INTERFACE; i != ACTIVITY_LAST; i++) {
    threadStatus[i] = false;
  }

  for ( ; ; ) {
    if (this->GetContext()->GetApplication()->IsShuttingDown()) {
      break;
    }

    sleep(60);

    logThreadStatus();
  }
}

void
HeartbeatMonitor::logThreadStatus() {
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

  syslog(this->GetContext()->priority, "%s", ostr.str().c_str());
}

