# Build output setup
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/bin)

add_subdirectory(Crypto)

add_executable(${PROJECT_NAME} Maintest.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE Crypto PUBLIC cryptopp)
