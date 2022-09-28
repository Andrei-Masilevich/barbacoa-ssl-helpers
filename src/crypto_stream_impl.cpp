#include <ssl_helpers/shadowing.h>

#include "crypto_stream_impl.h"


namespace ssl_helpers {
namespace impl {

    __aes_encryption_stream::__aes_encryption_stream(const context& ctx,
                                                     const std::string& shadowed_key, const std::string& aad)
        : _aad(aad)
    {
        _shadowed_key = shadowed_key;
    }

    std::string __aes_encryption_stream::start(const std::string& shadowed_key, const std::string& aad)
    {
        SSL_HELPERS_ASSERT(!shadowed_key.empty() || !_shadowed_key.empty(), "Key required");

        auto secret_key = from_shadow(shadowed_key.empty() ? _shadowed_key : shadowed_key);
        auto result = _sm.start(secret_key, aad.empty() ? _aad : aad);
        erase_in_memory(secret_key);
        return result;
    }

    std::string __aes_encryption_stream::encrypt(const std::string& plain_chunk)
    {
        return _sm.process(plain_chunk);
    }

    gcm_tag_type __aes_encryption_stream::finalize()
    {
        return _sm.finalize();
    }

    size_t __aes_encryption_stream::tag_size()
    {
        return std::tuple_size<gcm_tag_type>::value;
    }

    __aes_decryption_stream::__aes_decryption_stream(const context& ctx,
                                                     const std::string& shadowed_key, const std::string& aad)
        : _aad(aad)
    {
        _shadowed_key = shadowed_key;
    }

    void __aes_decryption_stream::start(const std::string& shadowed_key, const std::string& aad)
    {
        SSL_HELPERS_ASSERT(!shadowed_key.empty() || !_shadowed_key.empty(), "Key required");

        auto secret_key = from_shadow(shadowed_key.empty() ? _shadowed_key : shadowed_key);
        _sm.start(secret_key, aad.empty() ? _aad : aad);
        erase_in_memory(secret_key);
    }

    std::string __aes_decryption_stream::decrypt(const std::string& cipher_chunk)
    {
        return _sm.process(cipher_chunk);
    }

    void __aes_decryption_stream::finalize(const gcm_tag_type& tag)
    {
        _sm.finalize(tag);
    }

} // namespace impl

} // namespace ssl_helpers
