#include "cryptor.h"

#ifdef WITH_BORINGSSL
#include "boringssl_cryptor.h"
#else
#include "openssl_cryptor.h"
#endif

namespace discord {
namespace dave {

std::unique_ptr<ICryptor> CreateCryptor(const EncryptionKey& encryptionKey)
{
#ifdef WITH_BORINGSSL
    auto cryptor = std::make_unique<BoringSSLCryptor>(encryptionKey);
#else
    auto cryptor = std::make_unique<OpenSSLCryptor>(encryptionKey);
#endif

    return cryptor->IsValid() ? std::move(cryptor) : nullptr;
}

} // namespace dave
} // namespace discord
