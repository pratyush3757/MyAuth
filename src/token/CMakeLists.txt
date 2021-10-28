set(LIB_TOKEN_SRC
    src/token_hmac.cpp
    src/token_io.cpp
    src/token_hex.cpp
    src/token_hotp.cpp
)

add_library(lib_token
    ${LIB_TOKEN_SRC}
)

target_include_directories(lib_token PUBLIC include)
