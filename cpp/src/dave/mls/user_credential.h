#pragma once

#include <string>

#include <mls/credential.h>

#include "dave/version.h"

namespace discord::dave::mls {

::mlspp::Credential CreateUserCredential(const std::string& userId, ProtocolVersion version);
std::string UserCredentialToString(const ::mlspp::Credential& cred, ProtocolVersion version);

} // namespace discord::dave::mls
