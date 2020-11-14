#include "gps_utils.h"
#include <math.h>

// http://www.geodatasource.com/developers/c

#define pi 3.14159265358979323846

static double deg2rad(double deg);
static double rad2deg(double rad);

double
getDistance(double lat1, double lon1, double lat2, double lon2) {
  double R = 60 * 1.1515 * 1.609344; // km
  double theta = lon1 - lon2;
  double d = rad2deg(acos(sin(deg2rad(lat1)) * sin(deg2rad(lat2)) +
                     cos(deg2rad(lat1)) * cos(deg2rad(lat2)) *
                     cos(deg2rad(theta)))) * R;

  return d;
}

/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
/*::  This function converts decimal degrees to radians             :*/
/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
double deg2rad(double deg) {
  return (deg * pi / 180);
}
 
/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
/*::  This function converts radians to decimal degrees             :*/
/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
double rad2deg(double rad) {
  return (rad * 180 / pi);
}
