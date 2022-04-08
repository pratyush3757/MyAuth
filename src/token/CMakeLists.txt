set(LIB_TOKEN_SRC
    src/token_hmac.cpp
    src/token_io.cpp
    src/token_hex.cpp
    src/token_hotp.cpp
    src/token_totp.cpp
)

add_library(lib_token
    ${LIB_TOKEN_SRC}
)

target_link_libraries(lib_token lib_datatypes)

target_include_directories(lib_token PUBLIC include)
