#include <ssl_helpers/utils.h>

#include "convert_helper.h"


namespace ssl_helpers {

bool is_little_endian()
{
    int num = 1;
    return *reinterpret_cast<char*>(&num) == 1;
}

static const char* SSL_HELPERS_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S";

std::time_t from_iso_string(const std::string& formatted, bool should_utc)
{
    return impl::from_iso_string(formatted, SSL_HELPERS_TIME_FORMAT, should_utc);
}

std::time_t from_iso_string(const std::string& formatted, const char* time_format, bool should_utc)
{
    return impl::from_iso_string(formatted, time_format, should_utc);
}

std::string to_iso_string(const std::time_t time, bool should_utc)
{
    return impl::to_iso_string(time, SSL_HELPERS_TIME_FORMAT, should_utc);
}

std::string to_iso_string(const std::time_t time, const char* time_format, bool should_utc)
{
    return impl::to_iso_string(time, time_format, should_utc);
}

} // namespace ssl_helpers
