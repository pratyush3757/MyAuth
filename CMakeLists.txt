cmake_minimum_required(VERSION 3.21)

set(TESTNAME "test_runner")

# build source
project(my_auth VERSION 1.01.0
    DESCRIPTION "TOTP Authenticator"
    LANGUAGES CXX
)
set (CMAKE_CXX_STANDARD 20)
add_subdirectory(src)
target_include_directories(lib_my_auth PUBLIC include)

# build tests
project(${TESTNAME})

enable_testing()

add_subdirectory(test)

add_test(NAME ${TESTNAME} 
        COMMAND ${TESTNAME}
)
