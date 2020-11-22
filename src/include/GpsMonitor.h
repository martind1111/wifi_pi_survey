#ifndef _GPS_MONITOR_H
#define _GPS_MONITOR_H

#include <list>
#include <pthread.h>

#include "GpsTypes.h"
#include "Application.h"
#include "Worker.h"

void* MonitorGps(void* context);

class GpsMonitor : Worker {
public:
    GpsMonitor(ApplicationContext* context) : Worker(context),
        gpsMutex(PTHREAD_MUTEX_INITIALIZER) { }

    void Run() override;

    void ResetLocation();

private:
    void InitLocation();
    void ProcessGpsData(gps_data_t* data);
    void UpdateDistance(struct gps_fix_t* gps_fix);

    pthread_mutex_t gpsMutex;

    Location startLocation;

    time_t lastDistanceUpdate;

    Location lastDistanceLocation;

    std::list<Location> distanceLocations;
};

#endif // _GPS_MONITOR_H
