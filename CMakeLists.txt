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
find_package(OpenSSL REQUIRED)

# Find pkg-config and SQLCipher
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)

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
link_directories(${SQLCIPHER_LIBRARY_DIRS})

if (NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found. Please install it using your package manager.")
endif ()

# Add nlohmann_json
include(FetchContent)
FetchContent_Declare(
        json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        DOWNLOAD_EXTRACT_TIMESTAMP true
)
FetchContent_MakeAvailable(json)

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

# Define database sources
set(DATABASE_SOURCES
        src/database/database.cpp
        src/sql/queries.h
)

# Define cryptography sources and headers
set(CRYPTO_SOURCES
        src/key_exchange/DoubleRatchet.cpp
        src/key_exchange/x3dh.cpp
        src/key_exchange/DeviceCommunicationSession.cpp
        src/key_exchange/IdentityCommunicationSession.cpp
        src/key_exchange/XChaCha20-Poly1305.cpp
        src/utils/ConversionUtils.cpp
        src/client_api_interactions/MakeAuthReq.cpp
        src/client_api_interactions/MakeUnauthReq.cpp
        src/libraries/BaseClient.cpp
        src/libraries/HTTPSClient.cpp
        src/endpoints/endpoints.cpp
        src/auth/register_user/register_user.cpp
)

set(CRYPTO_HEADERS
        src/key_exchange/DoubleRatchet.h
        src/key_exchange/x3dh.h
        src/key_exchange/DeviceCommunicationSession.h
        src/key_exchange/utils.h
        src/algorithms/algorithms.cpp
        src/algorithms/algorithms.h
        src/key_exchange/XChaCha20-Poly1305.h
        src/utils/ConversionUtils.h
        src/libraries/BaseClient.h
        src/libraries/HTTPSClient.h
        src/libraries/BaseClient.cpp
        src/libraries/HTTPSClient.cpp
        src/endpoints/endpoints.cpp
        src/endpoints/endpoints.h
        src/auth/register_device/register_device.h
        src/auth/register_user/register_user.h
)

# Create main executable
add_executable(Eastwood
        src/main.cpp
        ${FRONTEND_SOURCES}
        ${DATABASE_SOURCES}
        ${CRYPTO_SOURCES}
        ${CRYPTO_HEADERS}
)

# Include directories and link libraries for main executable
target_include_directories(Eastwood PRIVATE
        ${SODIUM_INCLUDE_DIR}
        ${SQLCIPHER_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(Eastwood PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::UiTools
        ${SODIUM_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        ${SQLCIPHER_LIBRARIES}
)

# Create test executable
add_executable(EastwoodTests
        test/identity_communication_session_test.cpp
        ${CRYPTO_SOURCES}
)

# Configure test target
target_include_directories(EastwoodTests PRIVATE
    ${SODIUM_INCLUDE_DIR}
    ${SQLCIPHER_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/external/cereal/include
)

target_link_libraries(EastwoodTests PRIVATE
    ${SODIUM_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${SQLCIPHER_LIBRARIES}
)

# Enable testing
enable_testing()

# Add test
add_test(NAME EastwoodTests COMMAND EastwoodTests)
