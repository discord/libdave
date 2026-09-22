#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

#include "dave_test.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace discord {
namespace dave {
namespace test {

class CorpusRegressionTests : public DaveTests {};

// Replays every seed in the fuzz corpus through the fuzz entry point, under
// whatever sanitizers the build enables. This catches regressions on inputs
// that previously exercised parsing edge cases, and keeps the fuzz driver
// compiling on every platform the tests build on.
TEST_F(CorpusRegressionTests, ReplaysFuzzCorpus)
{
    const std::filesystem::path corpusDir(DAVE_FUZZ_CORPUS_DIR);
    ASSERT_TRUE(std::filesystem::is_directory(corpusDir));

    size_t replayed = 0;
    for (const auto& entry : std::filesystem::directory_iterator(corpusDir)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        std::ifstream file(entry.path(), std::ios::binary);
        ASSERT_TRUE(file.good());
        std::vector<char> bytes((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());

        LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
        ++replayed;
    }

    EXPECT_GT(replayed, 0u);
}

} // namespace test
} // namespace dave
} // namespace discord
