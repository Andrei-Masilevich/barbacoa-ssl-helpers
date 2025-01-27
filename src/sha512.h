#pragma once

#include <string>

#include <openssl/sha.h>


namespace ssl_helpers {
namespace impl {

    class sha512
    {
    public:
        sha512();
        explicit sha512(const std::string& hex_str);

        std::string str() const;
        operator std::string() const;

        char* data() const;
        size_t data_size() const { return 512 / 8; }

        static sha512 hash(const char* d, uint32_t dlen);
        static sha512 hash(const std::string&);

        template <typename T>
        static sha512 hash(const T& t)
        {
            sha512::encoder e;
            e << t;
            return e.result();
        }

        class encoder
        {
        public:
            encoder();
            ~encoder();

            void write(const char* d, uint32_t dlen);
            void put(char c) { write(&c, 1); }
            void reset();
            sha512 result();

        private:
            SHA512_CTX _context;
        };

        template <typename T>
        inline friend T& operator<<(T& ds, const sha512& ep)
        {
            ds.write(ep.data(), sizeof(ep));
            return ds;
        }

        template <typename T>
        inline friend T& operator>>(T& ds, sha512& ep)
        {
            ds.read(ep.data(), sizeof(ep));
            return ds;
        }
        friend sha512 operator<<(const sha512& h1, uint32_t i);
        friend bool operator==(const sha512& h1, const sha512& h2);
        friend bool operator!=(const sha512& h1, const sha512& h2);
        friend sha512 operator^(const sha512& h1, const sha512& h2);
        friend bool operator>=(const sha512& h1, const sha512& h2);
        friend bool operator>(const sha512& h1, const sha512& h2);
        friend bool operator<(const sha512& h1, const sha512& h2);

        uint64_t _hash[512 / 64];
    };

} // namespace impl
} // namespace ssl_helpers
