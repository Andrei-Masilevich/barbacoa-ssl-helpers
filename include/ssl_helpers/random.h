#pragma once

#include <string>
#include <vector>

#include <ssl_helpers/context.h>


namespace ssl_helpers {

// Generate pseudo random value from system time (high speed algorithm)

uint32_t create_pseudo_random_from_time(const uint32_t offset = 0);
std::string create_pseudo_random_string_from_time(const uint32_t offset = 0);


// Generate secure random value (slow algorithm)

uint64_t create_random(const context&);
std::string create_random_string(const context&, const size_t size, bool fixed = true);
void get_random(const context&, unsigned char* pbuff, size_t sz);

} // namespace ssl_helpers
