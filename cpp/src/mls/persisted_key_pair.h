#pragma once

#include <memory>
#include <string>
#include <vector>

#ifdef __ANDROID__
#include <jni.h>
#endif

#include <dave/dave_interfaces.h>
#include <dave/version.h>

namespace mlspp {
struct SignaturePrivateKey;
};

namespace discord {
namespace dave {
namespace mls {

std::shared_ptr<::mlspp::SignaturePrivateKey> GetPersistedKeyPair(KeyPairContextType ctx,
                                                                  const std::string& sessionID,
                                                                  ProtocolVersion version);

struct KeyAndSelfSignature {
    std::vector<uint8_t> key;
    std::vector<uint8_t> signature;
};

KeyAndSelfSignature GetPersistedPublicKey(KeyPairContextType ctx,
                                          const std::string& sessionID,
                                          SignatureVersion version);

bool DeletePersistedKeyPair(KeyPairContextType ctx,
                            const std::string& sessionID,
                            SignatureVersion version);

constexpr unsigned KeyVersion = 1;

} // namespace mls
} // namespace dave
} // namespace discord
