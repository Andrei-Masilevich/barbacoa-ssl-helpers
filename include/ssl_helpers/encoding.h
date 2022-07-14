#pragma once

#include <string>
#include <chrono>
#include <vector>


namespace ssl_helpers {

// Encode binary data to hexadecimal string

std::string to_hex(const std::string&);

// Decode binary data from hexadecimal string

std::string from_hex(const std::string&);


// Encode binary data to base58 string
// with '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' alphabet (Bitcoin style)

std::string to_base58(const std::string&);

// Decode binary data from base58 string

std::string from_base58(const std::string&);


// Encode binary data to base64 string

std::string to_base64(const std::string&);
std::string to_base64(const char*, size_t);

// Decode binary data from base64 string

std::string from_base64(const std::string&);
std::string from_base64(const char*, size_t);
// Initialize or append (if it is not empty) encoded data to result vector
void from_base64(const char*, size_t, std::vector<char>& result);

// Encode binary data to readable string one way only.
// It uses Python string.printable set but exclude few symbols by default

std::string to_printable(const std::string&,
                         char replace = '.',
                         const std::string& exclude = "\t\n\r\x0b\x0c");

} // namespace ssl_helpers
