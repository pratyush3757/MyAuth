# Build output setup
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test/bin)

################################
# GTest
################################
project(googletest-git NONE)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.11.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(BUILD_GTEST ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

################################
# Tests
################################
# All libraries to test
set(LIBS_TO_TEST
    cryptopp # Dependency
    lib_token
)
set(TEST_FILES
    token_hmac_tests.cpp
    token_hotp_tests.cpp
    token_totp_tests.cpp
)
# Add test cpp file
add_executable(${TESTNAME} ${TEST_FILES})
# Link test executable against gtest & gtest_main
target_link_libraries(${TESTNAME} gtest gtest_main ${LIBS_TO_TEST})
