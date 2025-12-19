#include "test_helpers.h"

#include <stdlib.h>
#include <string.h>

static int HexDigitToValue(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

uint8_t* GetBufferFromHex(const char* hex, size_t* outLength)
{
    if (!hex || !outLength) {
        return NULL;
    }

    size_t hexLength = strlen(hex);
    if (hexLength % 2 != 0) {
        *outLength = 0;
        return NULL;
    }

    size_t bufferLength = hexLength / 2;
    uint8_t* buffer = (uint8_t*)malloc(bufferLength);
    if (!buffer) {
        *outLength = 0;
        return NULL;
    }

    for (size_t i = 0; i < hexLength; i += 2) {
        int high = HexDigitToValue(hex[i]);
        int low = HexDigitToValue(hex[i + 1]);

        if (high < 0 || low < 0) {
            free(buffer);
            *outLength = 0;
            return NULL;
        }

        buffer[i / 2] = (uint8_t)((high << 4) | low);
    }

    *outLength = bufferLength;
    return buffer;
}
