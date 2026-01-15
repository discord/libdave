#include "openssl_cryptor.h"

#include <openssl/err.h>

#include <bytes/bytes.h>
#include <dave/logger.h>

#include "common.h"

namespace discord {
namespace dave {

void PrintSSLErrors()
{
    ERR_print_errors_cb(
      [](const char* str, size_t len, [[maybe_unused]] void* ctx) {
          DISCORD_LOG(LS_ERROR) << std::string(str, len);
          return 1;
      },
      nullptr);
}

OpenSSLCryptor::OpenSSLCryptor(const EncryptionKey& encryptionKey)
{
    if (!cipherCtx_) {
        cipherCtx_ = EVP_CIPHER_CTX_new();
    }
    else {
        EVP_CIPHER_CTX_reset(cipherCtx_);
    }

    auto initResult =
      EVP_CipherInit_ex(cipherCtx_, EVP_aes_128_gcm(), nullptr, encryptionKey.data(), nullptr, 0);

    if (initResult != 1) {
        DISCORD_LOG(LS_ERROR) << "Failed to initialize AEAD context";
        PrintSSLErrors();
    }
}

OpenSSLCryptor::~OpenSSLCryptor()
{
    EVP_CIPHER_CTX_free(cipherCtx_);
}

bool OpenSSLCryptor::Encrypt(ArrayView<uint8_t> ciphertextBufferOut,
                             ArrayView<const uint8_t> plaintextBuffer,
                             ArrayView<const uint8_t> nonceBuffer,
                             ArrayView<const uint8_t> additionalData,
                             ArrayView<uint8_t> tagBufferOut)
{
    if (!cipherCtx_) {
        DISCORD_LOG(LS_ERROR) << "Encrypt: AEAD context is not initialized";
        return false;
    }

    auto contextResult =
      EVP_EncryptInit_ex(cipherCtx_, nullptr, nullptr, nullptr, nonceBuffer.data());
    if (contextResult != 1) {
        DISCORD_LOG(LS_ERROR) << "Failed to set nonce for encryption";
        PrintSSLErrors();
        return false;
    }

    int ciphertextOutSize = 0;

    if (additionalData.size() > 0) {
        if (additionalData.size() > std::numeric_limits<int>::max()) {
            DISCORD_LOG(LS_ERROR) << "Additional data size exceeds the maximum supported size";
            return false;
        }

        auto aadResult = EVP_EncryptUpdate(cipherCtx_,
                                           nullptr,
                                           &ciphertextOutSize,
                                           additionalData.data(),
                                           static_cast<int>(additionalData.size()));

        if (aadResult != 1) {
            DISCORD_LOG(LS_ERROR) << "Failed to update encryption with additional data";
            PrintSSLErrors();
            return false;
        }
    }

    if (plaintextBuffer.size() > std::numeric_limits<int>::max()) {
        DISCORD_LOG(LS_ERROR) << "Plaintext buffer size exceeds the maximum supported size";
        return false;
    }

    auto updateResult = EVP_EncryptUpdate(cipherCtx_,
                                          ciphertextBufferOut.data(),
                                          &ciphertextOutSize,
                                          plaintextBuffer.data(),
                                          static_cast<int>(plaintextBuffer.size()));

    if (updateResult != 1) {
        DISCORD_LOG(LS_ERROR) << "Failed to encrypt plaintext";
        PrintSSLErrors();
        return false;
    }

    auto finalizeResult =
      EVP_EncryptFinal_ex(cipherCtx_, ciphertextBufferOut.data(), &ciphertextOutSize);
    if (finalizeResult != 1) {
        DISCORD_LOG(LS_ERROR) << "Failed to finalize encryption";
        PrintSSLErrors();
        return false;
    }

    auto tagResult = EVP_CIPHER_CTX_ctrl(
      cipherCtx_, EVP_CTRL_GCM_GET_TAG, kAesGcm128TruncatedTagBytes, tagBufferOut.data());
    if (tagResult != 1) {
        DISCORD_LOG(LS_ERROR) << "Failed to get truncated authentication tag";
        PrintSSLErrors();
        return false;
    }

    return true;
}

bool OpenSSLCryptor::Decrypt(ArrayView<uint8_t> plaintextBufferOut,
                             ArrayView<const uint8_t> ciphertextBuffer,
                             ArrayView<const uint8_t> tagBuffer,
                             ArrayView<const uint8_t> nonceBuffer,
                             ArrayView<const uint8_t> additionalData)
{
    if (!cipherCtx_) {
        DISCORD_LOG(LS_ERROR) << "Decrypt: AEAD context is not initialized";
        return false;
    }

    auto contextResult =
      EVP_DecryptInit_ex(cipherCtx_, nullptr, nullptr, nullptr, nonceBuffer.data());
    if (contextResult != 1) {
        DISCORD_LOG(LS_ERROR) << "Failed to set nonce for decryption";
        PrintSSLErrors();
        return false;
    }

    int plaintextOutSize = 0;

    if (additionalData.size() > 0) {
        if (additionalData.size() > std::numeric_limits<int>::max()) {
            DISCORD_LOG(LS_ERROR) << "Additional data size exceeds the maximum supported size";
            return false;
        }

        auto aadResult = EVP_DecryptUpdate(cipherCtx_,
                                           nullptr,
                                           &plaintextOutSize,
                                           additionalData.data(),
                                           static_cast<int>(additionalData.size()));

        if (aadResult != 1) {
            DISCORD_LOG(LS_ERROR) << "Failed to update decryption with additional data";
            PrintSSLErrors();
            return false;
        }
    }

    if (ciphertextBuffer.size() > std::numeric_limits<int>::max()) {
        DISCORD_LOG(LS_ERROR) << "Ciphertext buffer size exceeds the maximum supported size";
        return false;
    }

    auto updateResult = EVP_DecryptUpdate(cipherCtx_,
                                          plaintextBufferOut.data(),
                                          &plaintextOutSize,
                                          ciphertextBuffer.data(),
                                          static_cast<int>(ciphertextBuffer.size()));
    if (updateResult != 1) {
        DISCORD_LOG(LS_ERROR) << "Failed to decrypt ciphertext";
        PrintSSLErrors();
        return false;
    }

    // make a copy of the tag since the interface expects a const tag for decryption
    std::vector<uint8_t> tagBufferCopy(tagBuffer.begin(), tagBuffer.end());

    auto tagResult = EVP_CIPHER_CTX_ctrl(
      cipherCtx_, EVP_CTRL_GCM_SET_TAG, kAesGcm128TruncatedTagBytes, tagBufferCopy.data());
    if (tagResult != 1) {
        DISCORD_LOG(LS_ERROR)
          << "Failed to set expected truncated authentication tag for decryption";
        PrintSSLErrors();
        return false;
    }

    auto finalizeResult =
      EVP_DecryptFinal_ex(cipherCtx_, plaintextBufferOut.data(), &plaintextOutSize);
    if (finalizeResult != 1) {
        DISCORD_LOG(LS_ERROR) << "Failed to finalize decryption";
        PrintSSLErrors();
        return false;
    }

    return true;
}

} // namespace dave
} // namespace discord
