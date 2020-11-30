# Adding a gtest-based unit test
#
# Parameters:
#  - TEST_NAME
#  - TEST_SRCS
#  - TEST_LIBS
# TODO: Use cmake_parse_arguments()
# TODO: Check that parameters not null
set(GTEST_ROOT "/usr/include/gtest" CACHE PATH "Path to googletest")
find_package(GTest REQUIRED)
include(GoogleTest)

function(AddGoogleTest TEST_NAME TEST_SRCS TEST_LIBS)
    add_executable(${TEST_NAME} ${TEST_SRCS})
    target_link_libraries(
            ${TEST_NAME}
            PRIVATE
            gtest
            gtest_main
#            GTest::gtest
#            GTest::gtest_main
            PUBLIC
            ${TEST_LIBS})
    target_link_libraries(${TEST_NAME} PRIVATE project::settings)
    gtest_discover_tests(${TEST_NAME}
            # set a working directory so your project root so that you can find test data via paths relative to the project root
            WORKING_DIRECTORY ${PROJECT_DIR}
            PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${PROJECT_DIR}"
            )
    set_target_properties(${TEST_NAME} PROPERTIES FOLDER test)

endfunction()
