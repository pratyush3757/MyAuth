add_library(Crypto 
    src/Crypto_HMAC.cpp 
    src/Crypto_IO.cpp
    src/Crypto_Hex.cpp
    src/Crypto_HOTP.cpp
)

target_include_directories(Crypto PUBLIC include)
