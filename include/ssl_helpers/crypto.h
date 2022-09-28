#pragma once

#include <cstddef>

#include <string>
#include <functional>
#include <memory>

#include <ssl_helpers/context.h>

#include "crypto_types.h"


namespace ssl_helpers {

// Create ecrypted data stream that additionally includes tag (TAG) of encrypted data
// and optional marker that is AAD (Additional Authenticated Data).
// The TAG is subsequently used during the decryption operation to ensure that
// the ciphertext and AAD have not been tampered with.
// Data stream (from top down to bottom):
//
//     |AAD (can be readable data)|
//     |Encrypted data (binary)| -> transfering by chunks
//     |TAG (binary with 16 size)|
//

class aes_encryption_stream
{
public:
    aes_encryption_stream(const context&,
                          const std::string& default_shadowed_key = {},
                          const std::string& default_aad = {});
    ~aes_encryption_stream();

    // Start encryption session.
    std::string start(const std::string& shadowed_key = {},
                      const std::string& aad = {});

    // Encrypt chunk of data
    std::string encrypt(const std::string& plain_chunk);

    // Finalize encryption session and create tag.
    aes_tag_type finalize();

private:
    std::unique_ptr<impl::__aes_encryption_stream> _impl;
};


// Decrypt tagged encrypted data stream to original data.

class aes_decryption_stream
{
public:
    aes_decryption_stream(const context&,
                          const std::string& default_shadowed_key = {},
                          const std::string& default_aad = {});
    ~aes_decryption_stream();

    // Start decryption session.
    void start(const std::string& shadowed_key = {},
               const std::string& aad = {});

    // Decrypt chunk of cipher data.
    std::string decrypt(const std::string& cipher_chunk);

    // Finalize decryption session and check stream tag.
    void finalize(const aes_tag_type& tag);

    // Finalize decryption without check (for custom implementation)
    void finalize();

private:
    std::unique_ptr<impl::__aes_decryption_stream> _impl;
};


// Improve crypto resistance by using PBKDF2.

// Create random salt apply PBKDF2.
salted_key_type aes_create_salted_key(const context&, const std::string& key);

// Apply PBKDF2 for input salt.
std::string aes_get_salted_key(const std::string& key, const std::string& salt);
std::string aes_get_salted_key(const std::string& key, const aes_salt_type& salt);


// Encrypt data at once.

std::string aes_encrypt(const context&, const std::string& plain_data, const std::string& key);

// Provide authenticity of data with custom function.
std::string aes_encrypt(const context&,
                        const std::string& plain_data, const std::string& key,
                        std::function<std::string(const std::string& key, const std::string& cipher_data)> create_check_tag,
                        std::string& created_check_tag);

// Decrypt data at once.

std::string aes_decrypt(const context&,
                        const std::string& cipher_data, const std::string& key);

// Provide authenticity of data with custom function.
std::string aes_decrypt(const context&,
                        const std::string& cipher_data, const std::string& key,
                        const std::string& check_tag,
                        std::function<std::string(const std::string& key, const std::string& cipher_data)> create_check_tag);


// 'Flip/Flap' technique to transfer both encrypted data and key through unencrypted network.
// Idea is suppose data are transferred by three chunks separated in time
// and useless individually.
// This chunks are not classical cipher data, initialization vector
// and cipher key to prevent easy reveal. By default session key has unpredictable
// size (add_garbage) otherwise this chunk has fixed size.
// One can improve security if will transfer chunks via different data channels.
// Chunks:
//     1. Instant key
//     2. Cipher data
//     3. Session key

// Encrypt data at once (Flip).

flip_session_type aes_encrypt_flip(const context&,
                                   const std::string& plain_data,
                                   const std::string& instant_key,
                                   const std::string& marker = {},
                                   bool add_garbage = true);

// Decrypt data at once (Flap).

std::string aes_decrypt_flip(const context&,
                             const flip_session_type& session_data,
                             const std::string& instant_key,
                             const std::string& marker = {});
std::string aes_decrypt_flip(const context&,
                             const std::string& cipher_data,
                             const std::string& session_key,
                             const std::string& instant_key,
                             const std::string& marker = {});

} // namespace ssl_helpers
