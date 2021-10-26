cmake_minimum_required(VERSION 3.21)

set(TESTNAME "test_runner")

# build source
project(my_auth VERSION 0.03.0
    DESCRIPTION "TOTP Authenticator"
    LANGUAGES CXX
)
add_subdirectory(src)

# build tests
project(${TESTNAME})

enable_testing()
add_subdirectory(test)

add_test(NAME ${TESTNAME} 
        COMMAND ${TESTNAME}
)
