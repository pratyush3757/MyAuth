set(LIB_FILESYSTEM_IO_CRYPTO_SRC
    src/fs_io_crypto_filehandler.cpp
    src/fs_io_crypto_import.cpp
)

add_library(lib_filesystem_io_crypto
    ${LIB_FILESYSTEM_IO_CRYPTO_SRC}
)

target_link_libraries(lib_filesystem_io_crypto lib_datatypes)

target_include_directories(lib_filesystem_io_crypto PUBLIC include)

#get_filename_component(PARENT_DIR ../ ABSOLUTE)

#target_include_directories(lib_filesystem_io_crypto PUBLIC 
    #include 
#)
