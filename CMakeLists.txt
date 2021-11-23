cmake_minimum_required(VERSION 3.21)

set(TESTNAME "test_runner")

# build source
project(my_auth VERSION 0.05.1
    DESCRIPTION "TOTP Authenticator"
    LANGUAGES CXX
)
set (CMAKE_CXX_STANDARD 20)
add_subdirectory(src)

# build tests
project(${TESTNAME})

enable_testing()
add_subdirectory(test)

add_test(NAME ${TESTNAME} 
        COMMAND ${TESTNAME}
)
