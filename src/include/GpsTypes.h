#ifndef _GPS_TYPES_H
#define _GPS_TYPES_H

#include "gps.h"

struct Location {
    Location() : latitude(0.0), longitude(0.0), epx(0.0), epy(0.0),
        altitude(0.0), timestamp(0) {}
    double latitude;
    double longitude;
    double epx;
    double epy;
    double altitude;
    timestamp_t timestamp;
};

#endif // _GPS_TYPES_H
