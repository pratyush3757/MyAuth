cmake_minimum_required(VERSION 3.21)

project(MyAuth VERSION 0.01
    DESCRIPTION "TOTP Authenticator"
    LANGUAGES CXX
)

#unset(CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES)

add_subdirectory(Crypto)

add_executable(${PROJECT_NAME} Maintest.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE Crypto PUBLIC cryptopp)
