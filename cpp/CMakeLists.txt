cmake_minimum_required(VERSION 3.20)

project(
  libdave
  VERSION 1.0
  LANGUAGES CXX C
)

option(REQUIRE_BORINGSSL "Require BoringSSL instead of OpenSSL" OFF)
option(TESTING "Build tests" OFF)
option(PERSISTENT_KEYS "Enable storage of persistent signature keys" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)
option(INSTALL_VCPKG_LICENSES "Installs license files from vcpkg deps which require it" OFF)

include(CheckCXXCompilerFlag)
include(CMakeFindDependencyMacro)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -pedantic -Wextra -Werror -Wimplicit-int-conversion)
elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wall -pedantic -Wextra -Werror)
elseif(MSVC)
  add_compile_options(/W4 /WX)
  add_definitions(-DWINDOWS)

  # MSVC helpfully recommends safer equivalents for things like
  # getenv, but they are not portable.
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

# Configure sanitizers
if (ENABLE_SANITIZERS)
  if (NOT ${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    message(FATAL_ERROR "Sanitizers are only supported for Debug builds")
  endif()

  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(SANITIZER_FLAGS "-fsanitize=address,undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZER_FLAGS}")
    message(STATUS "Sanitizers enabled: address, undefined")
  elseif(MSVC)
    set(SANITIZER_FLAGS "/fsanitize=address /Zi")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
    # Disable STL container annotations to avoid mismatch with dependencies built without ASAN
    add_definitions(-D_DISABLE_STRING_ANNOTATION=1 -D_DISABLE_VECTOR_ANNOTATION=1)
    # Find ASAN runtime DLL for copying to test directories
    get_filename_component(COMPILER_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(ASAN_RUNTIME_DLL "${COMPILER_DIR}/clang_rt.asan_dynamic-x86_64.dll" CACHE FILEPATH "Path to ASAN runtime DLL")
    if(EXISTS "${ASAN_RUNTIME_DLL}")
      message(STATUS "ASAN runtime DLL: ${ASAN_RUNTIME_DLL}")
    else()
      message(WARNING "ASAN runtime DLL not found at ${ASAN_RUNTIME_DLL}")
    endif()
    message(STATUS "Sanitizers enabled: address")
  endif()
endif()

find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
  find_path(BORINGSSL_INCLUDE_DIR openssl/is_boringssl.h HINTS ${OPENSSL_INCLUDE_DIR} NO_DEFAULT_PATH)

  if (BORINGSSL_INCLUDE_DIR)
    message(STATUS "Found OpenSSL includes are for BoringSSL")
    
    add_compile_definitions(WITH_BORINGSSL)

    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
      add_compile_options(-Wno-gnu-anonymous-struct -Wno-nested-anon-types)
    endif ()

    file(STRINGS "${OPENSSL_INCLUDE_DIR}/openssl/crypto.h" boringssl_version_str
          REGEX "^#[\t ]*define[\t ]+OPENSSL_VERSION_TEXT[\t ]+\"OpenSSL ([0-9])+\\.([0-9])+\\.([0-9])+ .+")
    
    string(REGEX REPLACE "^.*OPENSSL_VERSION_TEXT[\t ]+\"OpenSSL ([0-9]+\\.[0-9]+\\.[0-9])+ .+$"
            "\\1" OPENSSL_VERSION "${boringssl_version_str}")

  elseif (REQUIRE_BORINGSSL)
    message(FATAL_ERROR "BoringSSL required but not found")
  endif ()

  if (${OPENSSL_VERSION} VERSION_GREATER_EQUAL 3)
    add_compile_definitions(WITH_OPENSSL3)
  elseif(${OPENSSL_VERSION} VERSION_LESS 1.1.1)
    message(FATAL_ERROR "OpenSSL 1.1.1 or greater is required")
  endif()

  message(STATUS "OpenSSL Found: ${OPENSSL_VERSION}")
  message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
  message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
else()
  message(FATAL_ERROR "No OpenSSL library found")
endif()

find_package(nlohmann_json REQUIRED)
find_dependency(MLSPP REQUIRED)

set(CMAKE_STATIC_LIBRARY_PREFIX "")

SET(LIB_NAME ${PROJECT_NAME})
file(GLOB_RECURSE LIB_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/includes/*.h")
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

# remove all of the persistent key files
list(FILTER LIB_SOURCES EXCLUDE REGEX ".*persisted_key.*")

if (PERSISTENT_KEYS)
  # persistent keys enabled
  list(APPEND LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/mls/persisted_key_pair.cpp")

  if (APPLE)
    # Apple has its own native and generic implementation, we just add the _apple.cpp file
    list(APPEND LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/mls/detail/persisted_key_pair_apple.cpp")
  else ()
    # Other platforms share the generic implementation
    list(APPEND LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/mls/detail/persisted_key_pair_generic.cpp")

    if (WIN32)
      # Windows has a native implementation
      list(APPEND LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/mls/detail/persisted_key_pair_win.cpp")
    else ()
      # We don't have a native implementation, so we include the nullified native
      list(APPEND LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/mls/detail/persisted_key_pair_null.cpp")
    endif ()
  endif ()
  
else ()
  # not using persistent keys, so we just need to add the null implementation
  list (APPEND LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/mls/persisted_key_pair_null.cpp")
endif ()

if (NOT WIN32)
  list(FILTER LIB_SOURCES EXCLUDE REGEX ".*_win.cpp")
endif ()

if (NOT APPLE)
  list(FILTER LIB_SOURCES EXCLUDE REGEX ".*_apple.cpp")
endif ()

if (NOT DEFINED EMSCRIPTEN)
  list(FILTER LIB_SOURCES EXCLUDE REGEX ".*_wasm.cpp")
else()
  list(FILTER LIB_SOURCES EXCLUDE REGEX ".*_capi.cpp")
endif()

if (BORINGSSL_INCLUDE_DIR)
  list(FILTER LIB_SOURCES EXCLUDE REGEX ".*openssl_cryptor.*")
else ()
  list(FILTER LIB_SOURCES EXCLUDE REGEX ".*boringssl_cryptor.*")
endif()

if (DEFINED EMSCRIPTEN)
  add_executable(${LIB_NAME} ${LIB_HEADERS} ${LIB_SOURCES})

  set(OPTIMIZATION "-O3")
  set(CONFIG "-sWASM=1 -sWASM_BIGINT -sENVIRONMENT=web -sMODULARIZE -sALLOW_MEMORY_GROWTH")
  set(EXPORTS "-sEXPORT_ES6=1 -sEXPORT_NAME=DaveModuleFactory -sEXPORTED_RUNTIME_METHODS='[\"ccall\"]' -sEXPORTED_FUNCTIONS='[\"_malloc\", \"_free\"]'")

  set(COMPILE_FLAGS "${OPTIMIZATION}")
  set(LINK_FLAGS "${OPTIMIZATION} ${CONFIG} ${EXPORTS} -lembind --no-entry --whole-archive --emit-tsd libdave.d.ts")

  set_target_properties(${LIB_NAME} PROPERTIES COMPILE_FLAGS "${COMPILE_FLAGS}")
  set_target_properties(${LIB_NAME} PROPERTIES LINK_FLAGS    "${LINK_FLAGS}")
else()
  add_library(${LIB_NAME} ${LIB_HEADERS} ${LIB_SOURCES})

  if (BUILD_SHARED_LIBS AND NOT WIN32)
    # Whithout this the resulting file is called liblibdave.dylib
    set_target_properties(${LIB_NAME} PROPERTIES OUTPUT_NAME dave)
  endif()
endif()

if (TESTING)
  add_subdirectory(test)
endif()

target_include_directories(
  ${LIB_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/includes>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
)

target_link_libraries(${LIB_NAME} PRIVATE OpenSSL::Crypto)
target_link_libraries(${LIB_NAME} PRIVATE MLSPP::mlspp)

if (APPLE AND PERSISTENT_KEYS)
  target_link_libraries(${LIB_NAME} PUBLIC "-framework CoreFoundation" "-framework Security")
endif()

set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY ON)

install(TARGETS ${LIB_NAME} INCLUDES DESTINATION "include")
install(DIRECTORY ${PROJECT_SOURCE_DIR}/includes/ DESTINATION "include")

if (INSTALL_VCPKG_LICENSES)
  set(DEPS_NEEDING_LICENSE mlspp nlohmann-json)
  if (BORINGSSL_INCLUDE_DIR)
    list(APPEND DEPS_NEEDING_LICENSE boringssl)
  else ()
    list(APPEND DEPS_NEEDING_LICENSE openssl)
  endif ()

  foreach(DEP_NAME ${DEPS_NEEDING_LICENSE})
    set(DEP_LICENSE_PATH "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/share/${DEP_NAME}")
    if (NOT EXISTS ${DEP_LICENSE_PATH})
      message(ERROR "Could not find license file for ${DEP_LICENSE_PATH}")
    endif()
    
    install(FILES ${DEP_LICENSE_PATH}/copyright DESTINATION "licenses" RENAME ${DEP_NAME})
  endforeach()
endif()

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../LICENSE DESTINATION "licenses" RENAME ${LIB_NAME})