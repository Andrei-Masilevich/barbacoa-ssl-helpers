#pragma once

#include <memory>

#include <ssl_helpers/context.h>

#include "ssl_helpers_defines.h"
#include "aes256.h"
#include "sha512.h"


namespace ssl_helpers {
namespace impl {

    // State Machine for encryption/decryption
    template <class aes_context>
    class aes_stream_sm
    {
        enum class state : uint8_t
        {
            finalized = 0,
            initialized,
            processing
        };

    public:
        aes_stream_sm() = default;

        std::string start(const std::string& key, const std::string& aad = {})
        {
            SSL_HELPERS_ASSERT(!key.empty(), "Key required");

            SSL_HELPERS_ASSERT(_state == state::finalized, "Invalid state");

            auto h_key = impl::sha512::hash(key);

            SSL_HELPERS_ASSERT(h_key.data_size() > 32);

            const char* ph_key = h_key.data();
            _context.init(create_from_string<gcm_key_type>(ph_key, h_key.data_size()),
                          create_from_string<gcm_iv_type>(ph_key + 32, h_key.data_size() - 32));
            if (!aad.empty())
                _context.set_aad(aad.data(), aad.size());

            _state = state::initialized;

            return aad;
        }

        std::string process(const std::string& plain_chunk)
        {
            SSL_HELPERS_ASSERT(_state == state::initialized || _state == state::processing, "Invalid state");

            _state = state::processing;

            std::vector<char> result(plain_chunk.size());
            auto sz = _context.process(plain_chunk.data(), plain_chunk.size(), result.data());
            result.resize(sz);

            return { result.data(), result.size() };
        }

        gcm_tag_type finalize(const gcm_tag_type& input_tag = {})
        {
            SSL_HELPERS_ASSERT(_state == state::processing, "Invalid state");

            _state = state::finalized;

            gcm_tag_type tag = input_tag;
            _context.finalize(tag);

            return tag;
        }

    private:
        aes_context _context;
        state _state = state::finalized;
    };

    class __aes_encryption_stream
    {
    public:
        __aes_encryption_stream(const context& ctx,
                                const std::string& shadowed_key, const std::string& aad);

        std::string start(const std::string& shadowed_key, const std::string& aad);
        std::string encrypt(const std::string& plain_chunk);
        gcm_tag_type finalize();

        static size_t tag_size();

    private:
        aes_stream_sm<aes_stream_encryptor> _sm;
        std::string _shadowed_key;
        std::string _aad;
    };

    class __aes_decryption_stream
    {
    public:
        __aes_decryption_stream(const context& ctx,
                                const std::string& shadowed_key, const std::string& aad);

        void start(const std::string& shadowed_key, const std::string& aad);
        std::string decrypt(const std::string& cipher_chunk);
        void finalize(const gcm_tag_type& tag);

    private:
        aes_stream_sm<aes_stream_decryptor> _sm;
        std::string _shadowed_key;
        std::string _aad;
    };

} // namespace impl
} // namespace ssl_helpers
