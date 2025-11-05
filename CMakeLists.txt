cmake_minimum_required(VERSION 3.16)
project(LucidioWebSocketServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Find Boost ---
find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# --- Find MongoDB C++ Driver ---
find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)

if(NOT mongocxx_FOUND)
    message(FATAL_ERROR "MongoDB C++ Driver is required")
endif()

# --- Build WebSocket Server ---
add_executable(websocket_server websocket_server.cpp)

target_include_directories(websocket_server PRIVATE 
    ${Boost_INCLUDE_DIRS}
    ${MONGOCXX_INCLUDE_DIRS}
    ${BSONCXX_INCLUDE_DIRS}
)

target_link_libraries(websocket_server
    PRIVATE
    ${Boost_LIBRARIES}
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    mongo::mongocxx_shared
    mongo::bsoncxx_shared
)

message(STATUS "✅ WebSocket server configured")