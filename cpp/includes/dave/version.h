#pragma once

#include <stdint.h>

#include <dave/dave.h>

namespace discord {
namespace dave {

using ProtocolVersion = uint16_t;
using SignatureVersion = uint8_t;

ProtocolVersion MaxSupportedProtocolVersion();

} // namespace dave
} // namespace discord
