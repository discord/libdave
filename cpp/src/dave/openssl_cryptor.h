#pragma once

#include <openssl/evp.h>

#include <bytes/bytes.h>

#include "dave/cryptor.h"

namespace discord {
namespace dave {

class OpenSSLCryptor : public ICryptor {
public:
    OpenSSLCryptor(const EncryptionKey& encryptionKey);
    ~OpenSSLCryptor();

    bool IsValid() const { return cipherCtx_ != nullptr; }

    bool Encrypt(ArrayView<uint8_t> ciphertextBufferOut,
                 ArrayView<const uint8_t> plaintextBuffer,
                 ArrayView<const uint8_t> nonceBuffer,
                 ArrayView<const uint8_t> additionalData,
                 ArrayView<uint8_t> tagBufferOut) override;
    bool Decrypt(ArrayView<uint8_t> plaintextBufferOut,
                 ArrayView<const uint8_t> ciphertextBuffer,
                 ArrayView<const uint8_t> tagBuffer,
                 ArrayView<const uint8_t> nonceBuffer,
                 ArrayView<const uint8_t> additionalData) override;

private:
    EVP_CIPHER_CTX* cipherCtx_ = nullptr;
    EncryptionKey encryptionKey_;
};

} // namespace dave
} // namespace discord
