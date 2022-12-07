#ifndef _DATATYPES_FLAGS_H_
#define _DATATYPES_FLAGS_H_

#include <cstdint>
#include <type_traits>

enum class SecretKeyFlags : std::uint8_t {
    ascii_secretKey = 0U << 0,
    base32_encoded_secretKey = 1U << 1,
    encrypted_secretKey = 1U << 0,
    hex_encoded_secretKey = 1U << 2, // For debugging use
    // ...
};

constexpr SecretKeyFlags operator| (SecretKeyFlags lhs, SecretKeyFlags rhs) {
    using underlying_t = typename std::underlying_type<SecretKeyFlags>::type;
 
    return static_cast<SecretKeyFlags>(
        static_cast<underlying_t>(lhs)
        | static_cast<underlying_t>(rhs)
        );
}

constexpr SecretKeyFlags operator& (SecretKeyFlags lhs, SecretKeyFlags rhs) {
    using underlying_t = typename std::underlying_type<SecretKeyFlags>::type;
 
    return static_cast<SecretKeyFlags>(
        static_cast<underlying_t>(lhs)
        | static_cast<underlying_t>(rhs)
        );
}

#endif
