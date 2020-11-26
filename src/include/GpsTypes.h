#ifndef _GPS_TYPES_H
#define _GPS_TYPES_H

#include "gps.h"

struct Location {
  double latitude;
  double longitude;
  double epx;
  double epy;
  double altitude;
  timestamp_t timestamp;
};

#endif // _GPS_TYPES_H
