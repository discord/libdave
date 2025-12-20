#include "user_credential.h"

#include <string>

#include "dave/mls/util.h"

namespace discord::dave::mls {

::mlspp::Credential CreateUserCredential(const std::string& userId,
                                         [[maybe_unused]] ProtocolVersion version)
{
    // convert the string user ID to a big endian uint64_t
    auto userID = std::stoull(userId);
    auto credentialBytes = BigEndianBytesFrom(userID);

    return ::mlspp::Credential::basic(credentialBytes);
}

std::string UserCredentialToString(const ::mlspp::Credential& cred,
                                   [[maybe_unused]] ProtocolVersion version)
{
    if (cred.type() != ::mlspp::CredentialType::basic) {
        return "";
    }

    const auto& basic = cred.template get<::mlspp::BasicCredential>();

    auto uidVal = FromBigEndianBytes(basic.identity);

    return std::to_string(uidVal);
}

} // namespace discord::dave::mls
