#pragma once

#include <string>
#include <chrono>

#include <ssl_helpers/context.h>


namespace ssl_helpers {

// Steganography helper to hide data in memory
// with XOR of random data

// Encrypt data

std::string nxor_encode_sec(const context&, const std::string& secret);
std::string nxor_encode(const std::string& secret);

// Decrypt data

std::string nxor_decode(const std::string& shadowed_secret);

// Cleanup

void erase_in_memory(std::string& secret, const std::string& rnd = {});

// Wrappers for the common cases

inline std::string to_shadow(std::string& secret, const std::string& rnd = {})
{
    auto shadowed_secret = nxor_encode(secret);
    erase_in_memory(secret, rnd);
    return shadowed_secret;
}

inline std::string from_shadow(const std::string& shadowed_secret)
{
    return nxor_decode(shadowed_secret);
}

} // namespace ssl_helpers
