cmake_minimum_required(VERSION 3.6)
project(jwk_generator CXX)
set(PROJECT_VERSION 1)

# c++17
set(STD 17)
if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD ${STD})
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
elseif(${CMAKE_CXX_STANDARD} LESS ${STD})
    message(FATAL_ERROR "jwk_generator requires c++${STD} or later")
endif()

# openssl
find_package(OpenSSL 3.0.5 REQUIRED)

# json
include(FetchContent)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
FetchContent_MakeAvailable(json)

# target
add_library(${PROJECT_NAME} INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/includes")

target_include_directories(${PROJECT_NAME} INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/includes"
    "${CMAKE_CURRENT_SOURCE_DIR}/lib/cppcodec")

target_link_libraries(${PROJECT_NAME} INTERFACE
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto)
