cmake_minimum_required(VERSION 3.13)

set(GTEST_ROOT "/usr/include/gtest" CACHE PATH "Path to googletest")
find_package(GTest REQUIRED)

add_library(${CMAKE_PROJECT_NAME}Test STATIC error_functions.c)

target_link_libraries(${CMAKE_PROJECT_NAME}Test PRIVATE ${CMAKE_PROJECT_NAME} pcap pcre sqlite3)

target_include_directories(${CMAKE_PROJECT_NAME}Test
  PUBLIC include
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

set(TEST_LIBS ${CMAKE_PROJECT_NAME} ${CMAKE_PROJECT_NAME}Test gtest)

set(MANUFACTURER_TEST_SRCS manufacturer.c)
AddGoogleTest(ManufacturerTest "${MANUFACTURER_TEST_SRCS}" "${TEST_LIBS}")
