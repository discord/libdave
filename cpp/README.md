## libdave C++

Contains the libdave C++ library, which handles the bulk of the DAVE protocol implementation for Discord's native clients.

### Dependencies

- [mlspp](https://github.com/cisco/mlspp)
  - Configured with `-DMLS_CXX_NAMESPACE="mlspp"` and `-DDISABLE_GREASE=ON`
- One of the supported SSL backends:
  - [OpenSSL 1.1 or 3.0](https://github.com/openssl/openssl)
  - [boringssl](https://boringssl.googlesource.com/boringssl)

#### Testing

- [googletest](https://github.com/google/googletest)
- [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)


## Building

### vcpkg

Make sure the vcpkg submodule is up to date and initialized:
```
git submodule update --recursive
./vcpkg/bootstrap-vcpkg.sh
```

### Compiling

For a static library, run:
```
make cclean
make
```

For a shared library, run:
```
make cclean
make shared
```

### SSL

By default the library builds with OpenSSL 3, however you can modify `VCPKG_MANIFEST_DIR` in the [Makefile](Makefile) to build with OpenSSL 1.1 or BoringSSL instead.