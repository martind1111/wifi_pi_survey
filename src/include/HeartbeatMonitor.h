#ifndef _HEARTBEAT_MONITOR_H
#define _HEARTBEAT_MONITOR_H

#include <map>
#include <pthread.h>

#include "Worker.h"
#include "HeartbeatTypes.h"

class ApplicationContext;

void* MonitorHeartbeat(void* context);

class HeartbeatMonitor : Worker {
public:
    HeartbeatMonitor(ApplicationContext* context) : Worker(context),
        threadStatusMutex(PTHREAD_MUTEX_INITIALIZER) { }

    void Run() override;

    void ReportActivity(const Activity_t activity);

private:
    void logThreadStatus();

    pthread_mutex_t threadStatusMutex;

    std::map<Activity_t, bool> threadStatus;
};

#endif // _HEARTBEAT_MONITOR_H
