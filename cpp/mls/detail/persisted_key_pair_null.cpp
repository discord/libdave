#include "dave/mls/detail/persisted_key_pair.h"

namespace discord {
namespace dave {
namespace mls {
namespace detail {

std::shared_ptr<::mlspp::SignaturePrivateKey> GetNativePersistedKeyPair(KeyPairContextType ctx,
                                                                        const std::string& keyID,
                                                                        ::mlspp::CipherSuite suite,
                                                                        bool& supported)
{
    supported = false;
    return nullptr;
}

bool DeleteNativePersistedKeyPair(KeyPairContextType ctx, const std::string& keyID)
{
    return false;
}

} // namespace detail
} // namespace mls
} // namespace dave
} // namespace discord
