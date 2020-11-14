#include <stdio.h>

#include "gps_utils.h"

int
main(int argc, char *argv[]) {
  double distance = getDistance(45.4423, -75.7941, 45.50866990, -73.55399250);

  fprintf(stdout, "Distance = %.6lf\n", distance);
}
