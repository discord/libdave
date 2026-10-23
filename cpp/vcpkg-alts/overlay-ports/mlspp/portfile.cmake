if("boringssl" IN_LIST FEATURES AND "openssl" IN_LIST FEATURES)
    message(FATAL_ERROR "mlspp features boringssl and openssl are mutually exclusive")
endif()
if(NOT "boringssl" IN_LIST FEATURES AND NOT "openssl" IN_LIST FEATURES)
    message(FATAL_ERROR "mlspp requires one of the boringssl or openssl features")
endif()

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO cisco/mlspp
    REF "${VERSION}"
    SHA512 5d37631e2c47daae1133ef074e60cc09ca2d395f9e11c416f829060e374051cf219d2d7fe98dae49d1d045292e07d6a09f4814a5f16e6cc05e67e7cd96f146c4
)

# libdave does not use these, and GCC 15 reports a -Werror false positive in mls_ds
vcpkg_replace_string("${SOURCE_PATH}/lib/CMakeLists.txt" "add_subdirectory(mls_ds)\n" "")
vcpkg_replace_string("${SOURCE_PATH}/lib/CMakeLists.txt" "add_subdirectory(mls_vectors)\n" "")

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
        boringssl REQUIRE_BORINGSSL
)

if(VCPKG_TARGET_IS_EMSCRIPTEN)
    string(APPEND VCPKG_C_FLAGS " -s WASM=1")
    string(APPEND VCPKG_CXX_FLAGS " -s WASM=1")
    string(APPEND VCPKG_LINKER_FLAGS " -s WASM=1 -s ALLOW_MEMORY_GROWTH=1")
endif()

if(VCPKG_TARGET_IS_OSX AND EXISTS "/usr/local/include/openssl/")
    set(VCPKG_INCLUDE_OVERRIDE "-DCMAKE_CXX_FLAGS=-I${CURRENT_INSTALLED_DIR}/include")
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        ${VCPKG_INCLUDE_OVERRIDE}
        -DDISABLE_GREASE=ON
        -DMLS_CXX_NAMESPACE="mlspp"
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME "MLSPP" CONFIG_PATH "share/MLSPP")
