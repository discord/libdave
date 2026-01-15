#pragma once

#include <bytes/bytes.h>
#include <mls/key_schedule.h>

#include <dave/dave_interfaces.h>

namespace discord {
namespace dave {

class MlsKeyRatchet : public IKeyRatchet {
public:
    MlsKeyRatchet(::mlspp::CipherSuite suite, bytes baseSecret) noexcept;
    ~MlsKeyRatchet() noexcept override;

    EncryptionKey GetKey(KeyGeneration generation) noexcept override;
    void DeleteKey(KeyGeneration generation) noexcept override;

    const ::mlspp::HashRatchet& GetHashRatchet() const noexcept { return hashRatchet_; }

private:
    ::mlspp::HashRatchet hashRatchet_;
};

} // namespace dave
} // namespace discord
