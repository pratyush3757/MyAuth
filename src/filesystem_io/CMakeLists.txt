set(LIB_FILESYSTEM_IO_SRC
    src/filesystem_io_uri.cpp
    src/filesystem_io_filehandler.cpp
)

add_library(lib_filesystem_io
    ${LIB_FILESYSTEM_IO_SRC}
)

target_link_libraries(lib_filesystem_io lib_datatypes)

add_subdirectory(crypto)

target_include_directories(lib_filesystem_io PUBLIC include)
target_include_directories(lib_filesystem_io_crypto PUBLIC include)
