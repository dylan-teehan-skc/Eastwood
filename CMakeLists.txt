cmake_minimum_required(VERSION 3.16)
project(Eastwood VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt
find_package(Qt6 REQUIRED COMPONENTS Widgets)

# Find Crypto++
find_path(CRYPTOPP_INCLUDE_DIR cryptopp/cryptlib.h
    PATHS /opt/homebrew/include
    NO_DEFAULT_PATH
)
find_library(CRYPTOPP_LIBRARY
    NAMES cryptopp
    PATHS /opt/homebrew/lib
    NO_DEFAULT_PATH
)

# Find libsodium
find_path(SODIUM_INCLUDE_DIR sodium.h
    PATHS /opt/homebrew/include
    /usr/local/include
    /usr/include
)
find_library(SODIUM_LIBRARY
    NAMES sodium libsodium
    PATHS /opt/homebrew/lib
    /usr/local/lib
    /usr/lib
)

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found. Please install it using your package manager.")
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Source files in cryptography directory
set(CRYPTO_SOURCES
    cryptography/DoubleRatchet.cpp
    cryptography/x3dh.cpp
    cryptography/CommunicationSession.cpp
)

# Header files in cryptography directory
set(CRYPTO_HEADERS
    cryptography/DoubleRatchet.h
    cryptography/x3dh.h
    cryptography/CommunicationSession.h
)

add_executable(Eastwood 
    main.cpp
    ${CRYPTO_SOURCES}
    ${CRYPTO_HEADERS}
)

target_include_directories(Eastwood PRIVATE 
    ${CRYPTOPP_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(Eastwood PRIVATE 
    Qt6::Widgets
    ${CRYPTOPP_LIBRARY}
    ${SODIUM_LIBRARY}
)

