cmake_minimum_required(VERSION 3.13)

project(wifi_pi_survey VERSION 1.0)
include(cmake/StandardProjectSettings.cmake)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Link against project_targets for projects options and warnings
add_library(project_settings INTERFACE)
add_library(project::settings ALIAS project_settings)
target_compile_features(project_settings INTERFACE cxx_std_17)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(
  "-fexceptions"
  "$<$<CONFIG:DEBUG>:-O0;-g3;-ggdb>"
)

#include(cmake/CompilerWarnings.cmake)
#set_project_warnings(project_settings)

# Sanitizer options if supported by compiler
#include(cmake/Sanitizers.cmake)
#enable_sanitizers(project_settings)

# Enable doxygen
#include(cmake/Doxygen.cmake)
#enable_doxygen()

# Allow for static analysis options
#include(cmake/StaticAnalyzers.cmake)

# Testing
option(ENABLE_TESTING "Enable Test Builds" OFF)
include(cmake/AddGoogleTest.cmake)

# Common libs
#find_package(Boost REQUIRED filesystem)

if (ENABLE_TESTING)
    enable_testing()
    message(
            "Building Tests."
    )
    add_subdirectory(tests)
endif ()

add_subdirectory(src)

