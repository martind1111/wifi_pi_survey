cmake_minimum_required(VERSION 3.13)

set(GTEST_ROOT "/usr/include/gtest" CACHE PATH "Path to googletest")
find_package(GTest REQUIRED)

add_library(${CMAKE_PROJECT_NAME}Test STATIC ${PROJECT_SOURCE_DIR}/HardwareHelper.cpp ${PROJECT_SOURCE_DIR}/gps_utils.c)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(TEST_LIBS ${CMAKE_PROJECT_NAME}Test pcap pcre gps sqlite3 wiringPi fmt pthread)

set(MANUFACTURER_TEST_SRCS ManufacturerTest.cpp)
AddGoogleTest(ManufacturerTest "${MANUFACTURER_TEST_SRCS}" "${TEST_LIBS}")

set(GPS_TEST_SRCS GpsTest.cpp)
AddGoogleTest(GpsTest "${GPS_TEST_SRCS}" "${TEST_LIBS}")
