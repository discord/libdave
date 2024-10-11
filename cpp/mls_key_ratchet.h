#pragma once

#include <mls/key_schedule.h>

#include "key_ratchet.h"

namespace discord {
namespace dave {

class MlsKeyRatchet : public IKeyRatchet {
public:
    MlsKeyRatchet(::MLS_NAMESPACE::CipherSuite suite, bytes baseSecret) noexcept;
    ~MlsKeyRatchet() noexcept override;

    EncryptionKey GetKey(KeyGeneration generation) noexcept override;
    void DeleteKey(KeyGeneration generation) noexcept override;

private:
    ::MLS_NAMESPACE::HashRatchet hashRatchet_;
};

} // namespace dave
} // namespace discord
