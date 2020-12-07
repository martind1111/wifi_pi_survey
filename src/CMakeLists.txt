set(BINARY wscand)

file(GLOB_RECURSE SOURCES LIST_DIRECTORIES true *.h *.c *.cc)
list(REMOVE_ITEM SOURCES ${CMAKE_SOURCE_DIR}/src/ExportKml.cc)

set(SOURCES ${SOURCES})

set(PROJECT_LINK_LIBS pcap pcre gps sqlite3 wiringPi fmt pthread ncurses)

add_executable(${BINARY} ${SOURCES})

target_link_libraries(${BINARY} LINK_PUBLIC ${PROJECT_LINK_LIBS})

install(TARGETS ${BINARY}
    RUNTIME DESTINATION bin
)

target_include_directories(${BINARY}
  PUBLIC include
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

set(EXPORT_KML_SOURCES ExportKml.cc StringHelper.cc)

add_executable(export_kml ${EXPORT_KML_SOURCES})

target_link_libraries(export_kml LINK_PUBLIC ${PROJECT_LINK_LIBS})

install(TARGETS export_kml
    RUNTIME DESTINATION bin
)

target_include_directories(export_kml
  PUBLIC include
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

