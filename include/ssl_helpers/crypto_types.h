#pragma once

#include <array>
#include <string>


namespace ssl_helpers {

using aes_512bit_type = std::array<char, 64>;
using aes_256bit_type = std::array<char, 32>;
using aes_128bit_type = std::array<char, 16>;

using aes_tag_type = aes_128bit_type;

using aes_salt_type = aes_128bit_type;
using salted_key_type = std::pair<std::string /*encryption key*/, aes_salt_type /*random salt*/>;

std::string aes_to_string(const aes_128bit_type&);
aes_128bit_type aes_from_string(const std::string&);

template <class _aes_type>
constexpr size_t aes_size()
{
    return _aes_type {}.size();
}

using flip_session_type = std::pair<std::string /*cipher data*/, std::string /*session key*/>;

namespace impl {
    class __aes_encryption_stream;
    class __aes_decryption_stream;
} // namespace impl

} // namespace ssl_helpers
