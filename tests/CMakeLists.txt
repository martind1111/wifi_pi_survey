cmake_minimum_required(VERSION 3.13)

set(GTEST_ROOT "/usr/include/gtest" CACHE PATH "Path to googletest")
find_package(GTest REQUIRED)

add_library(${CMAKE_PROJECT_NAME}Test STATIC ${PROJECT_SOURCE_DIR}/HardwareHelper.cc ${PROJECT_SOURCE_DIR}/gps_utils.c ${PROJECT_SOURCE_DIR}/radiotap.c ${PROJECT_SOURCE_DIR}/PacketDecoder.cc TestHelper.cc ${PROJECT_SOURCE_DIR}/PcapFileHandler.cc ${PROJECT_SOURCE_DIR}/PcapHandler.cc ${PROJECT_SOURCE_DIR}/Packet.cc)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(TEST_LIBS ${CMAKE_PROJECT_NAME}Test pcap pcre gps sqlite3 wiringPi fmt pthread boost_filesystem)

set(MANUFACTURER_TEST_SRCS ManufacturerTest.cc)
AddGoogleTest(ManufacturerTest "${MANUFACTURER_TEST_SRCS}" "${TEST_LIBS}")

set(GPS_TEST_SRCS GpsTest.cc)
AddGoogleTest(GpsTest "${GPS_TEST_SRCS}" "${TEST_LIBS}")

set(PACKET_DECODER_TEST_SRCS PacketDecoderTest.cc)
AddGoogleTest(PacketDecoderTest "${PACKET_DECODER_TEST_SRCS}" "${TEST_LIBS}")
