#include "GpsMonitor.h"

#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <math.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <termios.h>
#include <syslog.h>

#include <string>
#include <iostream>
#include <list>

#include <fmt/core.h>
#include "gps.h"
#include "libgpsmm.h"

extern "C" {
#include "gps_utils.h"
}

#include "HeartbeatMonitor.h"
#include "Application.h"

#define DISTANCE_LOCATION_SAMPLES 10

using namespace std;

namespace {
void GetAverageLocation(Location& location, list<Location>& locations);
}

void*
MonitorGps(void* ctx) {
    ApplicationContext* context = reinterpret_cast<ApplicationContext*>(ctx);
    GpsMonitor monitor(context);

    context->SetGpsMonitor(&monitor);

    monitor.Run();

    return nullptr;
}

void
GpsMonitor::Run() {
  InitLocation();

  gpsmm gps_rec("localhost", DEFAULT_GPSD_PORT);

  if (gps_rec.stream(WATCH_ENABLE|WATCH_JSON) == NULL) {
    cerr << "Daemon gpsd is not running.\n";
    return;
  }

  for ( ; ; ) {
    if (this->GetContext()->GetApplication()->IsShuttingDown()) {
      break;
    }

    this->GetMutableContext()->ReportActivity(ACTIVITY_MONITOR_GPS);

    struct gps_data_t* newdata;

    if (!gps_rec.waiting(50000000))
      continue;

    if ((newdata = gps_rec.read()) == NULL) {
      cerr << "Read error.\n";
      return;
    }
    else {
      ProcessGpsData(newdata);
    }
  }
}

void
GpsMonitor::InitLocation() {
  pthread_mutex_lock(&gpsMutex);

  this->GetMutableContext()->totalDistance = 0.0;

  startLocation.latitude = NAN;
  startLocation.longitude = NAN;
  startLocation.altitude = NAN;
  startLocation.epx = NAN;
  startLocation.epy = NAN;
  startLocation.timestamp = 0;

  this->GetMutableContext()->lastLocation.latitude = NAN;
  this->GetMutableContext()->lastLocation.longitude = NAN;
  this->GetMutableContext()->lastLocation.altitude = NAN;
  this->GetMutableContext()->lastLocation.epx = NAN;
  this->GetMutableContext()->lastLocation.epy = NAN;
  this->GetMutableContext()->lastLocation.timestamp = 0;

  lastDistanceLocation.latitude = NAN;
  lastDistanceLocation.longitude = NAN;
  lastDistanceLocation.altitude = NAN;
  lastDistanceLocation.epx = NAN;
  lastDistanceLocation.epy = NAN;
  lastDistanceLocation.timestamp = 0;

  pthread_mutex_unlock(&gpsMutex);
}

void
GpsMonitor::ProcessGpsData(gps_data_t* data) {
  struct gps_fix_t* gps_fix;

  gps_fix = &data->fix;

  pthread_mutex_lock(&gpsMutex);

  UpdateDistance(gps_fix);

  if (!isnan(gps_fix->latitude)) {
    if (isnan(startLocation.latitude)) {
      startLocation.latitude = gps_fix->latitude;
    }

    this->GetMutableContext()->lastLocation.latitude = gps_fix->latitude;
  }

  if (!isnan(gps_fix->longitude)) {
    if (isnan(startLocation.longitude)) {
      startLocation.longitude = gps_fix->longitude;
    }

    this->GetMutableContext()->lastLocation.longitude = gps_fix->longitude;
  }

  if (!isnan(gps_fix->altitude)) {
    if (isnan(startLocation.altitude)) {
      startLocation.altitude = gps_fix->altitude;
    }
    this->GetMutableContext()->lastLocation.altitude = gps_fix->altitude;
  }

  if (!isnan(gps_fix->epx)) {
    this->GetMutableContext()->lastLocation.epx = gps_fix->epx;
  }

  if (!isnan(gps_fix->epy)) {
    this->GetMutableContext()->lastLocation.epy = gps_fix->epy;
  }

  if (startLocation.timestamp == 0) {
    startLocation.timestamp = gps_fix->time;
  }

  this->GetMutableContext()->lastLocation.timestamp = gps_fix->time;

  pthread_mutex_unlock(&gpsMutex);

  // Output GPS information.
  if (!isnan(gps_fix->latitude) || !isnan(gps_fix->longitude) ||
      !isnan(gps_fix->altitude)) {
    fprintf(this->GetContext()->out, "GPS:\n");
  }

  if (!isnan(gps_fix->latitude)) {
    fprintf(this->GetContext()->out, "  Latitude = %lf\n", gps_fix->latitude);
  }

  if (!isnan(gps_fix->longitude)) {
    fprintf(this->GetContext()->out, "  Longitude = %lf\n", gps_fix->longitude);
  }

  if (!isnan(gps_fix->altitude)) {
    fprintf(this->GetContext()->out, "  Altitude = %lf\n", gps_fix->altitude);
  }
}

void
GpsMonitor::ResetLocation() {
  pthread_mutex_lock(&gpsMutex);

  this->GetMutableContext()->totalDistance = 0.0;

  startLocation.latitude = NAN;
  startLocation.longitude = NAN;
  startLocation.altitude = NAN;
  startLocation.epx = NAN;
  startLocation.epy = NAN;
  startLocation.timestamp = 0;

  pthread_mutex_unlock(&gpsMutex);
}

void
GpsMonitor::UpdateDistance(struct gps_fix_t* gps_fix) {
  struct timeval tv;

  if (gps_fix == NULL) {
    return;
  }

  if (gettimeofday(&tv, NULL) != 0) {
    return;
  }

  if (lastDistanceUpdate == 0) {
    lastDistanceUpdate = tv.tv_sec;

    return;
  }

  if (this->GetContext()->debugGps) { 
    string debugStr = fmt::format("GPS reading: Latitude {} longitude {}\n",
                                  gps_fix->latitude, gps_fix->longitude);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
  }

  Location location;

  if (!isnan(gps_fix->latitude) && !isnan(gps_fix->longitude)) {
    location.latitude = gps_fix->latitude;
    location.longitude = gps_fix->longitude;
    location.altitude = gps_fix->altitude;
    distanceLocations.push_back(location);
  }

  if (distanceLocations.size() < DISTANCE_LOCATION_SAMPLES) {
    return;
  }

  lastDistanceUpdate = tv.tv_sec;

  if (isnan(lastDistanceLocation.latitude) ||
      isnan(lastDistanceLocation.longitude)) {
    GetAverageLocation(location, distanceLocations);
  }
  else {
    int i;
    list<Location> shortest;
    list<pair<Location, double> > locations;

    list<Location>::iterator iter;
 
    for (iter = distanceLocations.begin(); iter != distanceLocations.end();
         iter++) {
      locations.push_back(
        std::make_pair(*iter,
                       getDistance(iter->latitude,
                                   lastDistanceLocation.latitude,
                                   iter->longitude,
                                   lastDistanceLocation.longitude)));
    }
   
    int num_samples =
      DISTANCE_LOCATION_SAMPLES > 3 ?
        DISTANCE_LOCATION_SAMPLES - 3 : DISTANCE_LOCATION_SAMPLES;

    for (i = 0; i < num_samples; i++) {
        double shortestDistance = 40000.0;

        list<pair<Location, double> >::iterator locIter;
        list<pair<Location, double> >::iterator shortLoc;

        for (locIter = locations.begin(); locIter != locations.end();
             locIter++) {
          if (locIter->second < shortestDistance) {
            shortLoc = locIter;
            shortestDistance = locIter->second;
          }
        }

        shortest.push_back(shortLoc->first);
        locations.erase(shortLoc);
    }

    GetAverageLocation(location, shortest);
  }

  if (this->GetContext()->debugGps) {
    string debugStr = fmt::format("Last average: Altitude {} longitude {}\n",
                                  lastDistanceLocation.latitude,
                                  lastDistanceLocation.longitude);

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());

    debugStr = fmt::format("Average: Altitude {} longitude {} ({})\n",
                           location.latitude, location.longitude,
                           distanceLocations.size());

    syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
  }

  if (!isnan(lastDistanceLocation.latitude) && !isnan(location.latitude) &&
      !isnan(lastDistanceLocation.longitude) && !isnan(location.longitude)) {
    double distance =
      getDistance(lastDistanceLocation.latitude, lastDistanceLocation.longitude,
                  location.latitude, location.longitude);
    if (!isnan(distance)) {
      if (this->GetContext()->debugGps) {
        string debugStr = fmt::format("Distance = {}", distance);

        syslog(LOG_USER | LOG_LOCAL3 | LOG_DEBUG, debugStr.c_str());
      }
      if (distance > 0.010) {
        this->GetMutableContext()->totalDistance += distance;
      }
    }
  }

  lastDistanceLocation.latitude = location.latitude;
  lastDistanceLocation.longitude = location.longitude;
  lastDistanceLocation.altitude = location.altitude;

  distanceLocations.clear();
}

namespace {
void
GetAverageLocation(Location& location, list<Location>& locations) {
    list<Location>::const_iterator iter;

    location.latitude = 0.0;
    location.longitude = 0.0;
    location.altitude = 0.0;

    for (iter = locations.begin(); iter != locations.end(); iter++) {
      location.latitude += iter->latitude;
      location.longitude += iter->longitude;
      location.altitude += iter->altitude;
    }

    location.latitude /= locations.size();
    location.longitude /= locations.size();
    location.altitude /= locations.size();
}
} // namespace
