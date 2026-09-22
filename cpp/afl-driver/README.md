# Fuzzing

`src/main.cpp` is a libFuzzer-interface fuzz target (`LLVMFuzzerTestOneInput`)
that feeds arbitrary input through frame decryption; `input/` is the seed
corpus.

## What runs automatically

- **Every CI run**: the corpus is replayed through the fuzz entry point as an
  ordinary test (`test/corpus_regression_tests.cpp`), on every platform and
  SSL backend, under whatever sanitizers the build enables. This also keeps
  the driver compiling everywhere.
- **PRs touching the parsing/decryption surface** (and manual dispatch): the
  `fuzz` workflow runs bounded coverage-guided fuzzing with ASan/UBSan.

## Fuzzing locally

Requires Clang (libFuzzer ships with it):

```
CC=clang CXX=clang++ make fuzz FUZZ_TIME=600
```

This builds the instrumented driver into `build/fuzz` and fuzzes for
`FUZZ_TIME` seconds, seeded from `input/`; newly-discovered corpus entries
accumulate in `build/fuzz/corpus` and findings (`crash-*` etc.) land in
`build/fuzz/`.

For long campaigns, [AFL++](https://github.com/AFLplusplus/AFLplusplus) also
runs this target: build the driver with `afl-clang-fast++` in place of the
libFuzzer link (the entry point is compatible), then
`afl-fuzz -i input -o findings -- ./dave_fuzzer`.

## Corpus

`input/` holds minimized seeds named `test-input-<sha1-prefix>.bin`. When a
fuzz run finds a crash, fix the bug and add the minimized reproducer to the
corpus so the regression test guards it forever:

```
build/fuzz/dave_fuzzer -minimize_crash=1 -exact_artifact_path=minimized <crash-file>
```

`fuzzer/FuzzedDataProvider.h` under `include/` is vendored verbatim from LLVM
(llvmorg-22.1.8) so the driver compiles with any toolchain; it is excluded
from repo formatting deliberately.
