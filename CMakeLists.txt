cmake_minimum_required(VERSION 3.16)
project(Eastwood VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Qt auto features
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets UiTools)

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

# Define frontend sources
set(FRONTEND_SOURCES
        src/ui/windows/login/login.cpp
        src/ui/windows/login/login.h
        src/ui/windows/login/login.ui
        src/ui/windows/register/register.cpp
        src/ui/windows/register/register.h
        src/ui/windows/register/register.ui
        src/ui/utils/messagebox.h
)

# Define cryptography sources and headers
set(CRYPTO_SOURCES
        src/key_exchange/DoubleRatchet.cpp
        src/key_exchange/x3dh.cpp
        src/key_exchange/CommunicationSession.cpp
)

set(CRYPTO_HEADERS
        src/key_exchange/DoubleRatchet.h
        src/key_exchange/x3dh.h
        src/key_exchange/CommunicationSession.h
        src/key_exchange/utils.h
)

# Create executable
add_executable(Eastwood
        src/main.cpp
    ${FRONTEND_SOURCES}
    ${CRYPTO_SOURCES}
    ${CRYPTO_HEADERS}
)

# Include directories and link libraries
target_include_directories(Eastwood PRIVATE 
    ${SODIUM_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(Eastwood PRIVATE 
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::UiTools
    ${SODIUM_LIBRARY}
)
