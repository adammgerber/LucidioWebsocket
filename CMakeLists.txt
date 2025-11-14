cmake_minimum_required(VERSION 3.16)
project(LucidioWebSocketServer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Detect Homebrew prefix automatically ---
if(EXISTS "/opt/homebrew")
    set(HOMEBREW_PREFIX "/opt/homebrew")   # Apple Silicon
elseif(EXISTS "/usr/local")
    set(HOMEBREW_PREFIX "/usr/local")      # Intel Macs
else()
    message(FATAL_ERROR "Homebrew not found! Please install Boost manually or specify BOOST_ROOT.")
endif()

set(BOOST_ROOT "${HOMEBREW_PREFIX}/opt/boost")
set(CMAKE_PREFIX_PATH "${BOOST_ROOT};${HOMEBREW_PREFIX}")

# Ensure CMake searches the right path first
list(APPEND CMAKE_SYSTEM_PREFIX_PATH "${HOMEBREW_PREFIX}")

# --- Dependencies ---
set(BOOST_ROOT "/opt/homebrew/opt/boost")
set(BOOST_INCLUDEDIR "${BOOST_ROOT}/include")
set(BOOST_LIBRARYDIR "${BOOST_ROOT}/lib")
set(Boost_NO_BOOST_CMAKE ON)
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(Boost 1.75.0 REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)
#kfk
if(Boost_FOUND)
    message(STATUS "✅ Found Boost ${Boost_VERSION}")
    message(STATUS "    Include dirs: ${Boost_INCLUDE_DIRS}")
    message(STATUS "    Library dirs: ${Boost_LIBRARY_DIRS}")
else()
    message(FATAL_ERROR "❌ Boost not found")
endif()

# --- MongoDB C++ Driver ---
find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)

if(mongocxx_FOUND)
    message(STATUS "✅ Found MongoDB C++ Driver")
    message(STATUS "    mongocxx include: ${MONGOCXX_INCLUDE_DIRS}")
    message(STATUS "    bsoncxx include: ${BSONCXX_INCLUDE_DIRS}")
else()
    message(FATAL_ERROR "❌ MongoDB C++ Driver not found")
endif()

# --- WebSocket Server ---
add_executable(websocket_server websocket_server.cpp)

target_link_libraries(websocket_server
    PRIVATE
    Threads::Threads
    mongo::mongocxx_shared
    mongo::bsoncxx_shared
    CURL::libcurl
)

target_include_directories(websocket_server PRIVATE 
    ${Boost_INCLUDE_DIRS}
    ${MONGOCXX_INCLUDE_DIRS}
    ${BSONCXX_INCLUDE_DIRS}
)

# Add libmongoc include directories if needed
target_include_directories(websocket_server PRIVATE
    ${HOMEBREW_PREFIX}/include/mongocxx/v_noabi
    ${HOMEBREW_PREFIX}/include/bsoncxx/v_noabi
    ${HOMEBREW_PREFIX}/include/libmongoc-1.0
    ${HOMEBREW_PREFIX}/include/libbson-1.0
)

message(STATUS "✅ WebSocket server will be built with MongoDB support")