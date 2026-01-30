# Options
BUILD_DIR=build
INSTALL_DIR=${BUILD_DIR}/install
SANITIZERS=OFF
BUILD_SHARED_LIBS=OFF
PERSISTENT_KEYS=OFF
TESTING=OFF
SSL=openssl_3
INSTALL_VCPKG_LICENSES=OFF

# Paths
BORINGSSL_MANIFEST=vcpkg-alts/boringssl
OPENSSL_1_1_MANIFEST=vcpkg-alts/openssl_1.1
OPENSSL_3_MANIFEST=vcpkg-alts/openssl_3
WASM_MANIFEST=vcpkg-alts/wasm
TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake
EMSCRIPTEN_TOOLCHAIN_FILE=${EMSDK}/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake

CLANG_FORMAT=clang-format -i -style=file:.clang-format

DEFAULT_BUILD_TYPE=Debug
BUILD_TYPE ?= $(DEFAULT_BUILD_TYPE)
all shared install: DEFAULT_BUILD_TYPE=Release

ifeq ($(SSL), boringssl)
	SSL_MANIFEST=${BORINGSSL_MANIFEST}
else ifeq ($(SSL), openssl_1.1)
	SSL_MANIFEST=${OPENSSL_1_1_MANIFEST}
else ifeq ($(SSL), openssl_3)
	SSL_MANIFEST=${OPENSSL_3_MANIFEST}
else
	$(error Invalid SSL option: $(SSL))
endif

ifeq ($(OS), Windows_NT)
	EXTRA_FLAGS=-DVCPKG_TARGET_TRIPLET=x64-windows-static \
		-DVCPKG_TARGET_ARCHITECTURE=x86_64
	ifeq ($(BUILD_TYPE), Debug)
		EXTRA_FLAGS+=-DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON
	endif
	ifdef MSVC_RUNTIME_LIBRARY
		EXTRA_FLAGS+=-DCMAKE_MSVC_RUNTIME_LIBRARY=${MSVC_RUNTIME_LIBRARY}
	endif
endif

all: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target libdave --config ${BUILD_TYPE}

${BUILD_DIR}: CMakeLists.txt test/CMakeLists.txt test/capi/CMakeLists.txt
	cmake -B${BUILD_DIR}  \
		-DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
		-DVCPKG_MANIFEST_DIR=${SSL_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE} \
		-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS} \
		-DENABLE_SANITIZERS=${SANITIZERS} \
		-DPERSISTENT_KEYS=${PERSISTENT_KEYS} \
		-DTESTING=${TESTING} \
		-DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} \
		-DINSTALL_VCPKG_LICENSES=${INSTALL_VCPKG_LICENSES} \
		${EXTRA_FLAGS}

install: ${BUILD_DIR}
	cmake --build ${BUILD_DIR} --target install --config ${BUILD_TYPE}

shared:
	$(MAKE) all BUILD_SHARED_LIBS=ON

dev:
	$(MAKE) all TESTING=ON BUILD_TYPE=$(BUILD_TYPE)

dev-shared:
	$(MAKE) dev BUILD_SHARED_LIBS=ON

dev-sanitizers:
	$(MAKE) dev SANITIZERS=ON

devB:
	# Like `dev`, but using OpenSSL 1.1
	$(MAKE) dev SSL=openssl_1.1

devC:
	# Like `dev`, but using BoringSSL
	$(MAKE) dev SSL=boringssl

wasm: check-emsdk
	emcmake cmake -B${BUILD_DIR} -DCMAKE_BUILD_TYPE=Release \
		-DVCPKG_MANIFEST_DIR=${WASM_MANIFEST} \
		-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE} \
		-DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=${EMSCRIPTEN_TOOLCHAIN_FILE} \
		-DVCPKG_TARGET_TRIPLET=wasm32-emscripten
	cmake --build ${BUILD_DIR} --target libdave --config ${BUILD_TYPE}

check-emsdk:
	@if [ -z "$$EMSDK" ]; then \
		echo "Error: EMSDK environment variable is not set"; \
		echo "Please set it to your emsdk installation directory"; \
		echo "Example: export EMSDK=/path/to/emsdk"; \
		exit 1; \
	fi

test: dev test/*
	cmake --build ${BUILD_DIR} --target libdave_test --config ${BUILD_TYPE}

test-capi: dev test/capi/*
	cmake --build ${BUILD_DIR} --target capi_test --config ${BUILD_TYPE}

test-sanitizers: dev-sanitizers test/*
	cmake --build ${BUILD_DIR} --target libdave_test --config ${BUILD_TYPE}

test-capi-sanitizers: dev-sanitizers test/capi/*
	cmake --build ${BUILD_DIR} --target capi_test --config ${BUILD_TYPE}

dtest: test
ifeq ($(OS), Windows_NT)
	${BUILD_DIR}/test/${BUILD_TYPE}/libdave_test.exe
else
	${BUILD_DIR}/test/libdave_test
endif

dtest-capi: test-capi
ifeq ($(OS), Windows_NT)
	${BUILD_DIR}/test/capi/${BUILD_TYPE}/capi_test.exe
else
	${BUILD_DIR}/test/capi/capi_test
endif

dtest-sanitizers: test-sanitizers
ifeq ($(OS), Windows_NT)
	${BUILD_DIR}/test/${BUILD_TYPE}/libdave_test.exe
else
	${BUILD_DIR}/test/libdave_test
endif

dtest-capi-sanitizers: test-capi-sanitizers
ifeq ($(OS), Windows_NT)
	${BUILD_DIR}/test/capi/${BUILD_TYPE}/capi_test.exe
else
	${BUILD_DIR}/test/capi/capi_test
endif

dbtest: test
	lldb ${BUILD_DIR}/test/libdave_test

dbtest-capi: test-capi
	lldb ${BUILD_DIR}/test/capi/capi_test

ctest: test
	cmake --build ${BUILD_DIR} --target test --config ${BUILD_TYPE}

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
ifeq ($(OS), Windows_NT)
	if exist ${BUILD_DIR} rmdir /s /q ${BUILD_DIR}
else
	rm -rf ${BUILD_DIR}
endif

format:
	find src -iname "*.h" -or -iname "*.cpp" -or -iname "*.c" | xargs ${CLANG_FORMAT}
	find test -iname "*.h" -or -iname "*.cpp" -or -iname "*.c" | xargs ${CLANG_FORMAT}
