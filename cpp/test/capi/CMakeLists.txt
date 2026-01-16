set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Small wrapper library for the external sender
SET(EXTERNAL_SENDER_WRAPPER_LIB "external_sender")
SET(EXTERNAL_SENDER_WRAPPER_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/../external_sender.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/external_sender_wrapper.cpp")
SET(EXTERNAL_SENDER_WRAPPER_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/../external_sender.h" "${CMAKE_CURRENT_SOURCE_DIR}/external_sender_wrapper.h")
add_library(${EXTERNAL_SENDER_WRAPPER_LIB} ${EXTERNAL_SENDER_WRAPPER_SOURCES} ${EXTERNAL_SENDER_WRAPPER_HEADERS})
target_include_directories(${EXTERNAL_SENDER_WRAPPER_LIB} PRIVATE ${PROJECT_SOURCE_DIR}/includes ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(${EXTERNAL_SENDER_WRAPPER_LIB} PRIVATE ${LIB_NAME} MLSPP::bytes MLSPP::mlspp)


SET(TEST_APP_NAME "capi_test")

file(GLOB_RECURSE TEST_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

add_executable(${TEST_APP_NAME} ${TEST_HEADERS} ${TEST_SOURCES})
add_dependencies(${TEST_APP_NAME} ${LIB_NAME} ${EXTERNAL_SENDER_WRAPPER_LIB})
target_include_directories(${TEST_APP_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/includes)

if (BUILD_SHARED_LIBS)
    set(LINKER_LANG C)
else()
    set(LINKER_LANG CXX)
endif()

set_target_properties(${TEST_APP_NAME} PROPERTIES LINKER_LANGUAGE ${LINKER_LANG})

target_link_libraries(${TEST_APP_NAME} PRIVATE ${LIB_NAME} ${EXTERNAL_SENDER_WRAPPER_LIB})

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

add_test(NAME ${TEST_APP_NAME} COMMAND ${TEST_APP_NAME})
