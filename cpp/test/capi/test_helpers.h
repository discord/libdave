#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stddef.h>
#include <stdint.h>

#define TEST_ASSERT(condition, message)                                              \
    do {                                                                             \
        if (!(condition)) {                                                          \
            fprintf(stderr, "FAILED: %s (at %s:%d)\n", message, __FILE__, __LINE__); \
            return 0;                                                                \
        }                                                                            \
    } while (0)

#define TEST_ASSERT_EQ(a, b, message)                                    \
    do {                                                                 \
        if ((a) != (b)) {                                                \
            fprintf(stderr,                                              \
                    "FAILED: %s - expected %lld, got %lld (at %s:%d)\n", \
                    message,                                             \
                    (long long)(b),                                      \
                    (long long)(a),                                      \
                    __FILE__,                                            \
                    __LINE__);                                           \
            return 0;                                                    \
        }                                                                \
    } while (0)

uint8_t* GetBufferFromHex(const char* hex, size_t* outLength);

#endif /* TEST_HELPERS_H */
