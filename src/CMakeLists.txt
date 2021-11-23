# Build output setup
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/bin)

add_subdirectory(token)
add_subdirectory(filesystem_io)

add_executable(${PROJECT_NAME} main_ui.cpp)

set(ALL_SUBLIBRARIES
    lib_token
    lib_filesystem_io
    lib_filesystem_io_crypto
)
set(ALL_DEPENDENCIES
    cryptopp
    ncurses
)
target_link_libraries(${PROJECT_NAME} PRIVATE ${ALL_SUBLIBRARIES} PUBLIC ${ALL_DEPENDENCIES})
