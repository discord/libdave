enable_testing()

find_package(GTest CONFIG REQUIRED)

SET(TEST_APP_NAME "libdave_test")

file(GLOB_RECURSE TEST_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(${TEST_APP_NAME} ${TEST_HEADERS} ${TEST_SOURCES})
add_dependencies(${TEST_APP_NAME} ${LIB_NAME})
target_include_directories(${TEST_APP_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(libdave_test PRIVATE ${LIB_NAME} GTest::gtest_main GTest::gmock MLSPP::bytes MLSPP::mlspp)

add_test(NAME ${TEST_APP_NAME} COMMAND ${TEST_APP_NAME})

if(WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(TARGET ${TEST_APP_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:${LIB_NAME}>
            $<TARGET_FILE_DIR:${TEST_APP_NAME}>
        COMMENT "Copying ${LIB_NAME}.dll to test directory"
    )
endif()

if(WIN32 AND ENABLE_SANITIZERS)
    if (NOT EXISTS "${ASAN_RUNTIME_DLL}")
        message(FATAL_ERROR "ASAN runtime DLL not found at ${ASAN_RUNTIME_DLL}")
    endif()

    add_custom_command(TARGET ${TEST_APP_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${ASAN_RUNTIME_DLL}"
            $<TARGET_FILE_DIR:${TEST_APP_NAME}>
        COMMENT "Copying ASAN runtime DLL to test directory"
    )
endif()

add_subdirectory(capi)