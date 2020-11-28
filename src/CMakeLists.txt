set(BINARY wscand)

file(GLOB_RECURSE SOURCES LIST_DIRECTORIES true *.h *.c *.cpp)
list(REMOVE_ITEM SOURCES ${CMAKE_SOURCE_DIR}/src/exportKml.cpp)

set(SOURCES ${SOURCES})

set(PROJECT_LINK_LIBS pcap pcre gps sqlite3 wiringPi fmt pthread)

add_executable(${BINARY} ${SOURCES})

target_link_libraries(${BINARY} LINK_PUBLIC ${PROJECT_LINK_LIBS})

install(TARGETS ${BINARY}
    RUNTIME DESTINATION bin
)

target_include_directories(${BINARY}
  PUBLIC include
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

set(EXPORT_KML_SOURCES exportKml.cpp StringHelper.cpp)

add_executable(exportKml ${EXPORT_KML_SOURCES})

target_link_libraries(exportKml LINK_PUBLIC ${PROJECT_LINK_LIBS})

install(TARGETS exportKml
    RUNTIME DESTINATION bin
)

target_include_directories(exportKml
  PUBLIC include
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

