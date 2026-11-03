#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <set>
#include <sstream>
#include <vector>

#include <emscripten.h>
#include <emscripten/bind.h>
#include <emscripten/console.h>
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

namespace {

std::atomic<LoggingSeverity> gMinLogSeverity = LS_INFO;

void WasmLogSink(LoggingSeverity severity, const char* file, int line, const std::string& message)
{
    if (severity < gMinLogSeverity.load() || severity == LS_NONE) {
        return;
    }

    if (auto separator = strrchr(file, '/')) {
        file = separator + 1;
    }

    std::ostringstream stream;
    stream << "(" << file << ":" << line << ") " << message;
    auto logLine = stream.str();

    switch (severity) {
    case LS_ERROR:
        emscripten_console_error(logLine.c_str());
        break;
    case LS_WARNING:
        emscripten_console_warn(logLine.c_str());
        break;
    default:
        emscripten_console_log(logLine.c_str());
        break;
    }
}

} // namespace

void SetLogSeverity(LoggingSeverity severity)
{
    gMinLogSeverity = severity;
}

LoggingSeverity GetLogSeverity()
{
    return gMinLogSeverity.load();
}

EMSCRIPTEN_DECLARE_VAL_TYPE(ByteInput);
EMSCRIPTEN_DECLARE_VAL_TYPE(ByteOutput);
EMSCRIPTEN_DECLARE_VAL_TYPE(OptionalByteOutput);
EMSCRIPTEN_DECLARE_VAL_TYPE(OptionalRoster);
EMSCRIPTEN_DECLARE_VAL_TYPE(CommitResult);
EMSCRIPTEN_DECLARE_VAL_TYPE(KeyRatchetInput);
EMSCRIPTEN_DECLARE_VAL_TYPE(KeyRatchetOutput);

// A JS exception unwinds the wasm stack without running destructors, so throw before allocating
[[noreturn]] void ThrowTypeError(const char* message)
{
    val::global("TypeError").new_(val(message)).throw_();
}

std::vector<uint8_t> BytesFromJS(const val& value)
{
    auto arrayBuffer = val::global("ArrayBuffer");
    val bytes = val::undefined();
    if (arrayBuffer.call<bool>("isView", value)) {
        bytes =
          val::global("Uint8Array").new_(value["buffer"], value["byteOffset"], value["byteLength"]);
    }
    else if (value.instanceof(arrayBuffer) || val::global("Array").call<bool>("isArray", value)) {
        bytes = val::global("Uint8Array").new_(value);
    }
    else {
        ThrowTypeError("expected an ArrayBuffer, ArrayBufferView or Array of bytes");
    }
    return convertJSArrayToNumberVector<uint8_t>(bytes);
}

// Copies out of the heap: a view's buffer would be the entire wasm memory
ByteOutput ToOwnedArrayBuffer(const uint8_t* data, size_t size)
{
    return ByteOutput(val::global("Uint8Array").new_(typed_memory_view(size, data))["buffer"]);
}

ByteOutput ToOwnedArrayBuffer(const ::mlspp::bytes_ns::bytes& data)
{
    return ToOwnedArrayBuffer(data.data(), data.size());
}

ByteOutput ToOwnedArrayBuffer(const std::vector<uint8_t>& data)
{
    return ToOwnedArrayBuffer(data.data(), data.size());
}

val RosterToJS(const RosterMap& roster)
{
    val rosterObj = val::object();
    for (const auto& [key, value] : roster) {
        rosterObj.set(key, ToOwnedArrayBuffer(value));
    }
    return rosterObj;
}

KeyRatchetOutput MlsKeyRatchetToJS(std::unique_ptr<MlsKeyRatchet> keyRatchet)
{
    if (!keyRatchet) {
        return KeyRatchetOutput(val::null());
    }

    auto hashRatchet = keyRatchet->GetHashRatchet();

    auto value = val::object();
    value.set("cipherSuite", static_cast<uint16_t>(hashRatchet.suite.cipher_suite()));
    value.set("baseSecret", ToOwnedArrayBuffer(hashRatchet.next_secret));

    return KeyRatchetOutput(value);
}

std::unique_ptr<MlsKeyRatchet> MlsKeyRatchetFromJS(const val& keyRatchet)
{
    if (keyRatchet.isNull()) {
        return nullptr;
    }

    auto cipherSuite = ::mlspp::CipherSuite(
      static_cast<::mlspp::CipherSuite::ID>(keyRatchet["cipherSuite"].as<uint16_t>()));
    auto baseSecret = BytesFromJS(keyRatchet["baseSecret"]);
    if (baseSecret.empty()) {
        ThrowTypeError("key ratchet baseSecret must not be empty");
    }

    return std::make_unique<MlsKeyRatchet>(cipherSuite, ::mlspp::bytes_ns::bytes(baseSecret));
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

    ByteOutput GetLastEpochAuthenticator()
    {
        return ToOwnedArrayBuffer(session_->GetLastEpochAuthenticator());
    }

    void SetExternalSender(ByteInput externalSender)
    {
        if (!externalSender.isNull()) {
            session_->SetExternalSender(BytesFromJS(externalSender));
        }
        else {
            DISCORD_LOG(LS_ERROR) << "External sender is null";
        }
    }

    void AddRecognizedUser(std::string userId) { session_->AddRecognizedUser(userId); }

    void RemoveRecognizedUser(std::string userId) { session_->RemoveRecognizedUser(userId); }

    OptionalByteOutput ProcessProposals(ByteInput proposals)
    {
        auto bytes = session_->ProcessProposals(BytesFromJS(proposals));
        if (!bytes) {
            return OptionalByteOutput(val::null());
        }
        return OptionalByteOutput(ToOwnedArrayBuffer(*bytes));
    }

    CommitResult ProcessCommit(ByteInput commit)
    {
        auto processedCommit = session_->ProcessCommit(BytesFromJS(commit));

        auto failed = std::holds_alternative<dave::failed_t>(processedCommit);
        auto ignored = std::holds_alternative<dave::ignored_t>(processedCommit);
        auto rosterUpdate = GetOptional<dave::RosterMap>(std::move(processedCommit));

        val result = val::object();
        result.set("failed", failed);
        result.set("ignored", ignored);

        result.set("rosterUpdate", rosterUpdate ? RosterToJS(*rosterUpdate) : val::null());
        return CommitResult(result);
    }

    OptionalRoster ProcessWelcome(ByteInput welcome)
    {
        auto roster = session_->ProcessWelcome(BytesFromJS(welcome));
        if (!roster) {
            return OptionalRoster(val::null());
        }
        return OptionalRoster(RosterToJS(*roster));
    }

    ByteOutput GetMarshalledKeyPackage()
    {
        return ToOwnedArrayBuffer(session_->GetMarshalledKeyPackage());
    }

    KeyRatchetOutput GetKeyRatchet(std::string const& userId)
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

    void SetKeyRatchet(KeyRatchetInput keyRatchet)
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

    void TransitionToKeyRatchet(KeyRatchetInput keyRatchet)
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
    discord::dave::SetLogSink(&discord::dave::WasmLogSink);

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

    enum_<discord::dave::LoggingSeverity>("LoggingSeverity")
      .value("LS_VERBOSE", discord::dave::LS_VERBOSE)
      .value("LS_INFO", discord::dave::LS_INFO)
      .value("LS_WARNING", discord::dave::LS_WARNING)
      .value("LS_ERROR", discord::dave::LS_ERROR)
      .value("LS_NONE", discord::dave::LS_NONE);

    register_type<discord::dave::ByteInput>("ArrayBuffer | ArrayBufferView | number[]");
    register_type<discord::dave::ByteOutput>("ArrayBuffer");
    register_type<discord::dave::OptionalByteOutput>("ArrayBuffer | null");
    register_type<discord::dave::OptionalRoster>("Record<string, ArrayBuffer> | null");
    register_type<discord::dave::CommitResult>(
      "{ failed: boolean; ignored: boolean; rosterUpdate: Record<string, ArrayBuffer> | null }");
    register_type<discord::dave::KeyRatchetInput>(
      "{ cipherSuite: number; baseSecret: ArrayBuffer | ArrayBufferView | number[] } | null");
    register_type<discord::dave::KeyRatchetOutput>(
      "{ cipherSuite: number; baseSecret: ArrayBuffer } | null");

    function("MaxSupportedProtocolVersion", &discord::dave::MaxSupportedProtocolVersion);
    function("SetLogSeverity", &discord::dave::SetLogSeverity);
    function("GetLogSeverity", &discord::dave::GetLogSeverity);

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
      .function("AddRecognizedUser", &discord::dave::mls::SessionWrapper::AddRecognizedUser)
      .function("RemoveRecognizedUser", &discord::dave::mls::SessionWrapper::RemoveRecognizedUser)
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
