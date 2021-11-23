set(LIB_FILESYSTEM_IO_CRYPTO_SRC
    src/fs_io_crypto_filehandler.cpp
)

add_library(lib_filesystem_io_crypto
    ${LIB_FILESYSTEM_IO_CRYPTO_SRC}
)

target_include_directories(lib_filesystem_io_crypto PUBLIC include)
