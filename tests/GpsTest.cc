#include <gtest/gtest.h>

extern "C" {
#include "gps_utils.h"
}

// Test the GPS getDistance API.
TEST(GpsTest, GetDistamce) {
  double distance = getDistance(45.4423, -75.7941, 45.50866990, -73.55399250);

  EXPECT_NEAR(distance, 174.806, 0.0005);
}
