set(BINARY wscan)

file(GLOB_RECURSE SOURCES LIST_DIRECTORIES true *.h *.c *.cpp)

set(SOURCES ${SOURCES})

set(PROJECT_LINK_LIBS pcap pcre gps sqlite3 wiringPi)

add_executable(${BINARY} ${SOURCES})

target_link_libraries(${BINARY} LINK_PUBLIC ${PROJECT_LINK_LIBS})

install(TARGETS ${BINARY}
    RUNTIME DESTINATION bin
)

target_include_directories(${BINARY}
  PUBLIC include
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

