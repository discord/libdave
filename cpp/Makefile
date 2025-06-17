BUILD_DIR=build
TEST_DIR=build/test
CLANG_FORMAT=clang-format -i -style=file:.clang-format
BORINGSSL_MANIFEST=vcpkg-alts/boringssl
OPENSSL_1_1_MANIFEST=vcpkg-alts/openssl_1.1
OPENSSL_3_MANIFEST=vcpkg-alts/openssl_3
TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target libdave

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt
	cmake -B${BUILD_DIR}  \
		-DVCPKG_MANIFEST_DIR=${OPENSSL_3_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

dev: ${TOOLCHAIN_FILE}
	cmake -B${BUILD_DIR} -DTESTING=ON -DCMAKE_BUILD_TYPE=Debug \
		-DVCPKG_MANIFEST_DIR=${OPENSSL_3_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

devB: ${TOOLCHAIN_FILE}
	# Like `dev`, but using OpenSSL 1.1
	cmake -B${BUILD_DIR} -DTESTING=ON -DCMAKE_BUILD_TYPE=Debug \
		-DVCPKG_MANIFEST_DIR=${OPENSSL_1_1_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

devC: ${TOOLCHAIN_FILE}
	# Like `dev`, but using BoringSSL
	cmake -B${BUILD_DIR} -DTESTING=ON -DCMAKE_BUILD_TYPE=Debug \
		-DREQUIRE_BORINGSSL=ON \
		-DVCPKG_MANIFEST_DIR=${BORINGSSL_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}

test: dev test/*
	cmake --build ${BUILD_DIR} --target libdave_test

dtest: test
	${TEST_DIR}/libdave_test

dbtest: test
	lldb ${TEST_DIR}/libdave_test

ctest: test
	cmake --build ${BUILD_DIR} --target test

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	rm -rf ${BUILD_DIR}

format:
	find src -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" | xargs ${CLANG_FORMAT}
