#pragma once

#include <stdint.h>

namespace discord::dave {

using ProtocolVersion = uint16_t;
using SignatureVersion = uint8_t;

ProtocolVersion MaxSupportedProtocolVersion();

} // namespace discord::dave
