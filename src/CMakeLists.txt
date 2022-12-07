# Build output setup
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/bin)

add_executable(${PROJECT_NAME} main_ui.cpp)

add_subdirectory(datatypes)
add_subdirectory(token)
add_subdirectory(filesystem_io)
add_subdirectory(crypto)
add_subdirectory(import_export)

set(ALL_SUBLIBRARIES
    lib_datatypes
    lib_token
    lib_filesystem_io
    lib_crypto
    lib_import_export
)
set(ALL_DEPENDENCIES
    cryptopp
    ncurses
)

target_link_libraries(lib_filesystem_io lib_datatypes lib_crypto lib_import_export)
#target_link_libraries(lib_crypto lib_filesystem_io)

target_link_libraries(${PROJECT_NAME} PRIVATE ${ALL_SUBLIBRARIES} PUBLIC ${ALL_DEPENDENCIES})

add_library(lib_my_auth my_auth.cpp)

target_link_libraries(lib_my_auth PUBLIC ${ALL_SUBLIBRARIES} ${ALL_DEPENDENCIES})
