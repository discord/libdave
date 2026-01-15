#pragma once

#include <stdint.h>

#include <dave.h>

namespace discord {
namespace dave {

using ProtocolVersion = uint16_t;
using SignatureVersion = uint8_t;

DAVE_EXPORT ProtocolVersion MaxSupportedProtocolVersion();

} // namespace dave
} // namespace discord
