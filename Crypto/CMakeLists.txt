add_library(Crypto 
    src/Crypto_HMAC.cpp 
    src/Crypto_IO.cpp
)

target_include_directories(Crypto PUBLIC include)
