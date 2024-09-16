#include "persisted_key_pair.h"

namespace discord {
namespace dave {
namespace mls {

std::shared_ptr<::mlspp::SignaturePrivateKey> GetPersistedKeyPair(KeyPairContextType,
                                                                  const std::string&,
                                                                  ProtocolVersion)
{
    return nullptr;
}

bool DeletePersistedKeyPair(KeyPairContextType, const std::string&)
{
    return false;
}

} // namespace mls
} // namespace dave
} // namespace discord
