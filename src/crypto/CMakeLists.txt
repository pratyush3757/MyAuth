set(LIB_CRYPTO_SRC
    src/crypto_hmac.cpp 
    src/crypto_io.cpp
    src/crypto_hex.cpp
    src/crypto_hotp.cpp
)

add_library(lib_crypto 
    ${LIB_CRYPTO_SRC}
)

target_include_directories(lib_crypto PUBLIC include)
