set(LIB_CRYPTO_SRC
    src/crypto_authentication.cpp
    src/crypto_filehandler.cpp
    src/crypto_runtime.cpp
)

add_library(lib_crypto
    ${LIB_CRYPTO_SRC}
)

target_include_directories(lib_crypto PUBLIC include)

target_link_libraries(lib_crypto lib_datatypes lib_filesystem_io)

