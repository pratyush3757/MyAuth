set(LIB_IMPORT_EXPORT_SRC
    src/import_export_handler.cpp
)

add_library(lib_import_export
    ${LIB_IMPORT_EXPORT_SRC}
)

target_link_libraries(lib_import_export lib_datatypes lib_filesystem_io lib_crypto)

target_include_directories(lib_import_export PUBLIC include)

