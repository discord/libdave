vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO cisco/mlspp
    REF "${VERSION}"
    SHA512 5d37631e2c47daae1133ef074e60cc09ca2d395f9e11c416f829060e374051cf219d2d7fe98dae49d1d045292e07d6a09f4814a5f16e6cc05e67e7cd96f146c4
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS 
        -DDISABLE_GREASE=ON 
        -DVCPKG_MANIFEST_DIR="alternatives/openssl_1.1"
        -DMLS_CXX_NAMESPACE="mlspp"
)

vcpkg_cmake_install()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")