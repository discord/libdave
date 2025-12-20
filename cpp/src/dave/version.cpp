#include "version.h"

namespace discord::dave {

constexpr ProtocolVersion CurrentDaveProtocolVersion = 1;

ProtocolVersion MaxSupportedProtocolVersion()
{
    return CurrentDaveProtocolVersion;
}

} // namespace discord::dave
