#include "persisted_key_pair.h"

namespace discord {
namespace dave {
namespace mls {

std::shared_ptr<::mlspp::SignaturePrivateKey> GetPersistedKeyPair(
  [[maybe_unused]] KeyPairContextType,
  [[maybe_unused]] const std::string&,
  [[maybe_unused]] ProtocolVersion)
{
    return nullptr;
}

bool DeletePersistedKeyPair([[maybe_unused]] KeyPairContextType,
                            [[maybe_unused]] const std::string&,
                            [[maybe_unused]] SignatureVersion)
{
    return false;
}

} // namespace mls
} // namespace dave
} // namespace discord
