set(BINARY ${CMAKE_PROJECT_NAME})

file(GLOB_RECURSE SOURCES LIST_DIRECTORIES true *.h *.c *.cpp)

set(SOURCES ${SOURCES})

set(PROJECT_LINK_LIBS pcap pcre gps sqlite3 wiringPi)

add_library(${CMAKE_PROJECT_NAME} STATIC ${SOURCES})

target_include_directories(${CMAKE_PROJECT_NAME}
  PUBLIC include
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
