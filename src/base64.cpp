#include <memory.h>

#include "base64.h"
#include "ssl_helpers_defines.h"


namespace ssl_helpers {
namespace impl {
    namespace {
        static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                "abcdefghijklmnopqrstuvwxyz"
                                                "0123456789+/";

        using BYTE = unsigned char;

        static inline bool is_base64(BYTE c)
        {
            return (isalnum(c) || (c == '+') || (c == '/'));
        }

        std::string base64_encode(BYTE const* buf, unsigned int bufLen)
        {
            std::string ret;
            int i = 0;
            int j = 0;
            BYTE char_array_3[3];
            BYTE char_array_4[4];

            while (bufLen--)
            {
                char_array_3[i++] = *(buf++);
                if (i == 3)
                {
                    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                    char_array_4[3] = char_array_3[2] & 0x3f;

                    for (i = 0; (i < 4); i++)
                        ret += base64_chars[char_array_4[i]];
                    i = 0;
                }
            }

            if (i)
            {
                for (j = i; j < 3; j++)
                    char_array_3[j] = '\0';

                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (j = 0; (j < i + 1); j++)
                    ret += base64_chars[char_array_4[j]];

                while ((i++ < 3))
                    ret += '=';
            }

            return ret;
        }

        std::vector<BYTE> base64_decode(const char* encoded_string, size_t sz)
        {
            long in_len = static_cast<long>(sz);
            int i = 0;
            int j = 0;
            int in_ = 0;
            BYTE char_array_4[4], char_array_3[3];
            std::vector<BYTE> ret;

            while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
            {
                char_array_4[i++] = encoded_string[in_];
                in_++;
                if (i == 4)
                {
                    for (i = 0; i < 4; i++)
                        char_array_4[i] = base64_chars.find(char_array_4[i]);

                    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                    for (i = 0; (i < 3); i++)
                        ret.push_back(char_array_3[i]);
                    i = 0;
                }
            }

            if (i)
            {
                for (j = i; j < 4; j++)
                    char_array_4[j] = 0;

                for (j = 0; j < 4; j++)
                    char_array_4[j] = base64_chars.find(char_array_4[j]);

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (j = 0; (j < i - 1); j++)
                    ret.push_back(char_array_3[j]);
            }

            return ret;
        }
    } // namespace

    std::string to_base64(const char* d, size_t s)
    {
        return base64_encode(reinterpret_cast<const BYTE*>(d), static_cast<unsigned int>(s));
    }
    std::string to_base64(const std::vector<char>& d)
    {
        if (d.size())
            return to_base64(d.data(), d.size());
        return std::string();
    }

    std::vector<char> from_base64(const char* d, size_t s)
    {
        std::vector<BYTE> out = base64_decode(d, s);
        SSL_HELPERS_ASSERT(!out.empty(), "Unable to decode base58 string");
        return std::vector<char>((const char*)out.data(), ((const char*)out.data()) + out.size());
    }

    size_t from_base64(const char* d, size_t s, char* out_data, size_t out_data_len)
    {
        std::vector<BYTE> out = base64_decode(d, s);
        SSL_HELPERS_ASSERT(!out.empty(), "Unable to decode base58 string");
        SSL_HELPERS_ASSERT(out.size() <= out_data_len);
        if (!out.empty())
        {
            memcpy(out_data, out.data(), out.size());
        }
        return out.size();
    }

} // namespace impl
} // namespace ssl_helpers
