enable_testing()

find_package(GTest CONFIG REQUIRED)

SET(TEST_APP_NAME "libdave_test")

file(GLOB_RECURSE TEST_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(${TEST_APP_NAME} ${TEST_HEADERS} ${TEST_SOURCES})
add_dependencies(${TEST_APP_NAME} ${LIB_NAME})
target_include_directories(${TEST_APP_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(libdave_test PRIVATE ${LIB_NAME} GTest::gtest_main GTest::gmock MLSPP::bytes)

add_test(NAME ${TEST_APP_NAME} COMMAND ${TEST_APP_NAME})

# Add C API tests if shared library is built
if (BUILD_SHARED_LIBS)
    add_subdirectory(capi)
endif()