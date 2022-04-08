add_library(lib_datatypes
    datatypes.cpp
)
target_include_directories(lib_datatypes PUBLIC "${CMAKE_CURRENT_LIST_DIR}/include")

add_executable(datatypes_test datatypes_main.cpp datatypes.cpp)
target_include_directories(datatypes_test PUBLIC "${CMAKE_CURRENT_LIST_DIR}/include")
target_link_libraries(datatypes_test PUBLIC cryptopp)
