#include <cstdint>
#include <memory>
#include <set>
#include <vector>

#include <emscripten.h>
#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <mls/crypto.h>
#include <mls/key_schedule.h>

#include <dave/logger.h>
#include <dave/version.h>

#include "common.h"
#include "decryptor.h"
#include "encryptor.h"
#include "mls/parameters.h"
#include "mls/session.h"
#include "mls_key_ratchet.h"

using namespace emscripten;

namespace discord {
namespace dave {

val ToOwnedTypedArray(const uint8_t* data, size_t size)
{
    val array = val::array();
    for (size_t i = 0; i < size; i++) {
        array.call<void>("push", data[i]);
    }
    return array;
}

val ToOwnedTypedArray(const ::mlspp::bytes_ns::bytes& data)
{
    return ToOwnedTypedArray(data.data(), data.size());
}

val ToOwnedTypedArray(const std::vector<uint8_t>& data)
{
    return ToOwnedTypedArray(data.data(), data.size());
}

val MlsKeyRatchetToJS(std::unique_ptr<MlsKeyRatchet> keyRatchet)
{
    if (!keyRatchet) {
        return val::null();
    }

    auto hashRatchet = keyRatchet->GetHashRatchet();

    auto value = val::object();
    value.set("cipherSuite", static_cast<uint16_t>(hashRatchet.suite.cipher_suite()));
    value.set("baseSecret", ToOwnedTypedArray(hashRatchet.next_secret));

    return value;
}

std::unique_ptr<MlsKeyRatchet> MlsKeyRatchetFromJS(val keyRatchet)
{
    if (keyRatchet.isNull()) {
        return nullptr;
    }

    auto cipherSuite = ::mlspp::CipherSuite(
      static_cast<::mlspp::CipherSuite::ID>(keyRatchet["cipherSuite"].as<uint16_t>()));
    auto baseSecret = emscripten::convertJSArrayToNumberVector<uint8_t>(keyRatchet["baseSecret"]);
    auto baseSecretBytes = ::mlspp::bytes_ns::bytes(baseSecret);

    return std::make_unique<MlsKeyRatchet>(cipherSuite, baseSecretBytes);
}

namespace mls {

class TransientKeys {
public:
    std::shared_ptr<::mlspp::SignaturePrivateKey> GetTransientPrivateKey(ProtocolVersion version)
    {
        auto it = keys_.find(version);
        if (it == keys_.end()) {
            auto ciphersuite = CiphersuiteForProtocolVersion(version);
            auto key = std::make_shared<::mlspp::SignaturePrivateKey>(
              ::mlspp::SignaturePrivateKey::generate(ciphersuite));
            it = keys_.emplace(version, key).first;
        }
        return it->second;
    }

    void Clear() { keys_.clear(); }

private:
    std::map<ProtocolVersion, std::shared_ptr<::mlspp::SignaturePrivateKey>> keys_;
};

class SessionWrapper {
public:
    SessionWrapper(std::string ctx, std::string authSessionId, val callback)
    {
        session_ = std::make_unique<Session>(
          ctx.c_str(), authSessionId, [callback](std::string source, std::string message) {
              callback(source, message);
          });
    }

    void Init(ProtocolVersion version,
              uint64_t groupId,
              std::string const& selfUserId,
              std::shared_ptr<::mlspp::SignaturePrivateKey>& transientKey)
    {
        session_->Init(version, groupId, selfUserId, transientKey);
    }

    void Reset() { session_->Reset(); }

    void SetProtocolVersion(ProtocolVersion version) { session_->SetProtocolVersion(version); }

    ProtocolVersion GetProtocolVersion() { return session_->GetProtocolVersion(); }

    val GetLastEpochAuthenticator()
    {
        return ToOwnedTypedArray(session_->GetLastEpochAuthenticator());
    }

    void SetExternalSender(val externalSender)
    {
        if (!externalSender.isNull()) {
            std::vector<uint8_t> externalSenderVec =
              emscripten::convertJSArrayToNumberVector<uint8_t>(externalSender);
            session_->SetExternalSender(externalSenderVec);
        }
        else {
            DISCORD_LOG(LS_ERROR) << "External sender is null";
        }
    }

    val ProcessProposals(val proposals, val recognizedUserIDs)
    {
        std::vector<uint8_t> proposalsVec =
          emscripten::convertJSArrayToNumberVector<uint8_t>(proposals);
        auto recognizedUserIDsVec = emscripten::vecFromJSArray<std::string>(recognizedUserIDs);
        auto recognizedUserIDsSet =
          std::set<std::string>(recognizedUserIDsVec.begin(), recognizedUserIDsVec.end());

        auto bytes = session_->ProcessProposals(proposalsVec, recognizedUserIDsSet);
        if (!bytes) {
            return val::null();
        }
        return ToOwnedTypedArray(*bytes);
    }

    val ProcessCommit(val commit)
    {
        std::vector<uint8_t> commitVec = emscripten::convertJSArrayToNumberVector<uint8_t>(commit);
        auto processedCommit = session_->ProcessCommit(commitVec);

        auto failed = std::holds_alternative<dave::failed_t>(processedCommit);
        auto ignored = std::holds_alternative<dave::ignored_t>(processedCommit);
        auto rosterUpdate = GetOptional<dave::RosterMap>(std::move(processedCommit));

        val result = val::object();
        result.set("failed", failed);
        result.set("ignored", ignored);

        val rosterObj = val::null();
        if (rosterUpdate) {
            rosterObj = val::object();
            for (const auto& [key, value] : *rosterUpdate) {
                rosterObj.set(key, ToOwnedTypedArray(value));
            }
        }
        result.set("rosterUpdate", rosterObj);
        return result;
    }

    val ProcessWelcome(val welcome, val recognizedUserIDs)
    {
        auto welcomeVec = emscripten::convertJSArrayToNumberVector<uint8_t>(welcome);
        auto recognizedUserIDsVec = emscripten::vecFromJSArray<std::string>(recognizedUserIDs);
        auto recognizedUserIDsSet =
          std::set<std::string>(recognizedUserIDsVec.begin(), recognizedUserIDsVec.end());
        auto roster = session_->ProcessWelcome(welcomeVec, recognizedUserIDsSet);
        if (!roster) {
            return val::null();
        }

        val rosterObj = val::object();
        for (const auto& [key, value] : *roster) {
            rosterObj.set(key, ToOwnedTypedArray(value));
        }

        return rosterObj;
    }

    val GetMarshalledKeyPackage() { return ToOwnedTypedArray(session_->GetMarshalledKeyPackage()); }

    val GetKeyRatchet(std::string const& userId)
    {
        auto keyRatchet = session_->GetKeyRatchet(userId);
        auto mlsKeyRatchet =
          std::unique_ptr<MlsKeyRatchet>(static_cast<MlsKeyRatchet*>(keyRatchet.release()));
        return MlsKeyRatchetToJS(std::move(mlsKeyRatchet));
    }

private:
    std::unique_ptr<mls::Session> session_;
};

} // namespace mls

class EncryptorWrapper {
public:
    EncryptorWrapper() { encryptor_ = std::make_unique<Encryptor>(); }

    void SetKeyRatchet(val keyRatchet)
    {
        encryptor_->SetKeyRatchet(MlsKeyRatchetFromJS(keyRatchet));
    }

    void SetPassthroughMode(bool passthroughMode)
    {
        encryptor_->SetPassthroughMode(passthroughMode);
    }

    void AssignSsrcToCodec(uint32_t ssrc, Codec codecType)
    {
        encryptor_->AssignSsrcToCodec(ssrc, codecType);
    }

    ProtocolVersion GetProtocolVersion() { return encryptor_->GetProtocolVersion(); }

    size_t GetMaxCiphertextByteSize(MediaType mediaType, size_t plaintextByteSize)
    {
        return encryptor_->GetMaxCiphertextByteSize(mediaType, plaintextByteSize);
    }

    size_t Encrypt(MediaType mediaType,
                   uint32_t ssrc,
                   int framePtr,
                   size_t frameLength,
                   size_t frameCapacity)
    {
        auto frame = reinterpret_cast<uint8_t*>(framePtr);

        auto frameView = MakeArrayView(const_cast<const uint8_t*>(frame), frameLength);
        auto encryptedFrameMaxSize = GetMaxCiphertextByteSize(mediaType, frameLength);
        if (frameCapacity < encryptedFrameMaxSize) {
            DISCORD_LOG(LS_ERROR) << "Frame capacity is less than the maximum ciphertext size";
            return 0;
        }
        auto encryptedFrameView = MakeArrayView(frame, encryptedFrameMaxSize);

        size_t bytesWritten = 0;
        auto result =
          encryptor_->Encrypt(mediaType, ssrc, frameView, encryptedFrameView, &bytesWritten);

        if (result != 0) {
            return 0;
        }

        return bytesWritten;
    }

    void SetProtocolVersionChangedCallback(val callback)
    {
        encryptor_->SetProtocolVersionChangedCallback([callback]() { callback(); });
    }

private:
    std::unique_ptr<Encryptor> encryptor_;
};

class DecryptorWrapper {
public:
    DecryptorWrapper() { decryptor_ = std::make_unique<Decryptor>(); }

    void TransitionToKeyRatchet(val keyRatchet)
    {
        decryptor_->TransitionToKeyRatchet(MlsKeyRatchetFromJS(keyRatchet));
    }

    void TransitionToPassthroughMode(bool passthroughMode)
    {
        decryptor_->TransitionToPassthroughMode(passthroughMode);
    }

    size_t GetMaxPlaintextByteSize(MediaType mediaType, size_t ciphertextByteSize)
    {
        return decryptor_->GetMaxPlaintextByteSize(mediaType, ciphertextByteSize);
    }

    size_t Decrypt(MediaType mediaType, int framePtr, size_t frameLength, size_t frameCapacity)
    {
        auto frame = reinterpret_cast<uint8_t*>(framePtr);
        auto frameView = MakeArrayView(const_cast<const uint8_t*>(frame), frameLength);
        auto maxPlaintextByteSize = decryptor_->GetMaxPlaintextByteSize(mediaType, frameLength);

        if (frameCapacity < maxPlaintextByteSize) {
            DISCORD_LOG(LS_ERROR) << "Frame capacity is less than the maximum plaintext size";
            return 0;
        }
        auto plaintextView = MakeArrayView(frame, maxPlaintextByteSize);

        size_t bytesWritten = 0;
        auto result = decryptor_->Decrypt(mediaType, frameView, plaintextView, &bytesWritten);
        if (result != Decryptor::ResultCode::Success) {
            return 0;
        }
        return bytesWritten;
    }

private:
    std::unique_ptr<Decryptor> decryptor_;
};

} // namespace dave
} // namespace discord

EMSCRIPTEN_BINDINGS(dave)
{
    constant("kInitTransitionId", discord::dave::kInitTransitionId);
    constant("kDisabledVersion", discord::dave::kDisabledVersion);

    enum_<discord::dave::MediaType>("MediaType")
      .value("Audio", discord::dave::MediaType::Audio)
      .value("Video", discord::dave::MediaType::Video);

    enum_<discord::dave::Codec>("Codec")
      .value("Unknown", discord::dave::Codec::Unknown)
      .value("Opus", discord::dave::Codec::Opus)
      .value("VP8", discord::dave::Codec::VP8)
      .value("VP9", discord::dave::Codec::VP9)
      .value("H264", discord::dave::Codec::H264)
      .value("H265", discord::dave::Codec::H265)
      .value("AV1", discord::dave::Codec::AV1);

    function("MaxSupportedProtocolVersion", &discord::dave::MaxSupportedProtocolVersion);

    class_<::mlspp::SignaturePrivateKey>("SignaturePrivateKey")
      .smart_ptr<std::shared_ptr<::mlspp::SignaturePrivateKey>>("SignaturePrivateKeyPtr");

    class_<discord::dave::mls::TransientKeys>("TransientKeys")
      .constructor<>()
      .function("GetTransientPrivateKey",
                &discord::dave::mls::TransientKeys::GetTransientPrivateKey)
      .function("Clear", &discord::dave::mls::TransientKeys::Clear);

    class_<discord::dave::mls::SessionWrapper>("Session")
      .constructor<std::string, std::string, val>()
      .function("Init", &discord::dave::mls::SessionWrapper::Init)
      .function("Reset", &discord::dave::mls::SessionWrapper::Reset)
      .function("SetProtocolVersion", &discord::dave::mls::SessionWrapper::SetProtocolVersion)
      .function("GetProtocolVersion", &discord::dave::mls::SessionWrapper::GetProtocolVersion)
      .function("GetLastEpochAuthenticator",
                &discord::dave::mls::SessionWrapper::GetLastEpochAuthenticator)
      .function("SetExternalSender", &discord::dave::mls::SessionWrapper::SetExternalSender)
      .function("ProcessProposals", &discord::dave::mls::SessionWrapper::ProcessProposals)
      .function("ProcessCommit", &discord::dave::mls::SessionWrapper::ProcessCommit)
      .function("ProcessWelcome", &discord::dave::mls::SessionWrapper::ProcessWelcome)
      .function("GetMarshalledKeyPackage",
                &discord::dave::mls::SessionWrapper::GetMarshalledKeyPackage)
      .function("GetKeyRatchet", &discord::dave::mls::SessionWrapper::GetKeyRatchet);

    class_<discord::dave::EncryptorWrapper>("Encryptor")
      .constructor<>()
      .function("SetKeyRatchet", &discord::dave::EncryptorWrapper::SetKeyRatchet)
      .function("SetPassthroughMode", &discord::dave::EncryptorWrapper::SetPassthroughMode)
      .function("AssignSsrcToCodec", &discord::dave::EncryptorWrapper::AssignSsrcToCodec)
      .function("GetProtocolVersion", &discord::dave::EncryptorWrapper::GetProtocolVersion)
      .function("GetMaxCiphertextByteSize",
                &discord::dave::EncryptorWrapper::GetMaxCiphertextByteSize)
      .function(
        "Encrypt", &discord::dave::EncryptorWrapper::Encrypt, emscripten::allow_raw_pointers())
      .function("SetProtocolVersionChangedCallback",
                &discord::dave::EncryptorWrapper::SetProtocolVersionChangedCallback);

    class_<discord::dave::DecryptorWrapper>("Decryptor")
      .constructor<>()
      .function("TransitionToKeyRatchet", &discord::dave::DecryptorWrapper::TransitionToKeyRatchet)
      .function("TransitionToPassthroughMode",
                &discord::dave::DecryptorWrapper::TransitionToPassthroughMode)
      .function("GetMaxPlaintextByteSize",
                &discord::dave::DecryptorWrapper::GetMaxPlaintextByteSize)
      .function(
        "Decrypt", &discord::dave::DecryptorWrapper::Decrypt, emscripten::allow_raw_pointers());
}
