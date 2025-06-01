cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0135 NEW)
project(Eastwood VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Qt auto features
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets UiTools Concurrent)
find_package(OpenSSL REQUIRED)
find_package(OpenCV REQUIRED)


# Add nlohmann_json
include(FetchContent)
FetchContent_Declare(
        json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        DOWNLOAD_EXTRACT_TIMESTAMP true
)
FetchContent_MakeAvailable(json)

# Fetch GoogleTest - following official guide
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Enable testing - following official guide
enable_testing()
include(GoogleTest)

# Fetch QR Code Generator
FetchContent_Declare(
        qrcodegen
        GIT_REPOSITORY https://github.com/nayuki/QR-Code-generator.git
        GIT_TAG master
)

FetchContent_MakeAvailable(qrcodegen)

# Find pkg-config and SQLCipher
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)

link_directories(${SQLCIPHER_LIBRARY_DIRS})

# Find libsodium
find_path(SODIUM_INCLUDE_DIR sodium.h
        PATHS
        /usr/include
        /usr/local/include
        /opt/homebrew/include
        /usr/include/x86_64-linux-gnu
        /usr/include/aarch64-linux-gnu
        NO_DEFAULT_PATH
)
find_library(SODIUM_LIBRARY
        NAMES sodium libsodium
        PATHS
        /usr/lib
        /usr/local/lib
        /opt/homebrew/lib
        /usr/lib/x86_64-linux-gnu
        /usr/lib/aarch64-linux-gnu
        NO_DEFAULT_PATH
)
link_directories(${SQLCIPHER_LIBRARY_DIRS})

if (NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found. Please install it using your package manager.")
endif ()

message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
message(STATUS "Found sodium.h: ${SODIUM_INCLUDE_DIR}")

# Define frontend sources
set(FRONTEND_SOURCES
        src/ui/windows/login/login.cpp
        src/ui/windows/login/login.h
        src/ui/windows/login/login.ui
        src/ui/windows/register/register.cpp
        src/ui/windows/register/register.h
        src/ui/windows/register/register.ui
        src/ui/windows/device_register/device_register.cpp
        src/ui/windows/device_register/device_register.h
        src/ui/windows/device_register/device_register.ui
        src/ui/utils/messagebox.h
        src/ui/windows/received_dashboard/received_dash.cpp
        src/ui/windows/received_dashboard/received_dash.h
        src/ui/windows/received_dashboard/received_dash.ui
        src/ui/windows/sent_dashboard/sent_dash.cpp
        src/ui/windows/sent_dashboard/sent_dash.h
        src/ui/windows/sent_dashboard/sent_dash.ui
        src/ui/windows/send_file/send_file.cpp
        src/ui/windows/send_file/send_file.h
        src/ui/windows/send_file/send_file.ui
        src/ui/resources.qrc
        src/ui/utils/file_item_widget/file_item_widget.cpp
        src/ui/utils/file_item_widget/file_item_widget.h
        src/ui/utils/navbar/navbar.cpp
        src/ui/utils/navbar/navbar.h
        src/ui/utils/navbar/navbar.ui
        src/ui/utils/window_manager/window_manager.cpp
        src/ui/utils/window_manager/window_manager.h
        src/ui/windows/settings/settings.cpp
        src/ui/windows/settings/settings.h
        src/ui/windows/settings/settings.ui
        src/sessions/RatchetSessionManager.cpp
        src/sessions/RatchetSessionManager.h
        src/ui/utils/qr_code_generation/QRCodeGenerator.cpp
        src/ui/utils/qr_code_generation/QRCodeGenerator.h
        src/ui/utils/camera_functionality/camera_functionality.cpp
)

# Define database sources
set(DATABASE_SOURCES
        src/database/database.cpp
        src/sql/queries.h
)

# Define cryptography sources and headers
set(CRYPTO_SOURCES
        src/key_exchange/x3dh.cpp
        src/key_exchange/XChaCha20-Poly1305.cpp
        src/key_exchange/NewRatchet.cpp
        src/key_exchange/NewRatchet.h
        src/utils/ConversionUtils.cpp
        src/utils/JsonParser.cpp
        src/client_api_interactions/MakeAuthReq.cpp
        src/client_api_interactions/MakeUnauthReq.cpp
        src/libraries/BaseClient.cpp
        src/libraries/HTTPSClient.cpp
        src/endpoints/endpoints.cpp
        src/keys/kek_manager.cpp
        src/keys/secure_memory_buffer.cpp
        src/keys/session_token_manager.cpp
        src/algorithms/algorithms.cpp
)

set(AUTH_SOURCES
        src/auth/register_user/register_user.cpp
        src/auth/register_device/register_device.cpp
        src/auth/login/login.cpp
        src/sessions/KeyBundle.h
        src/files/upload_file.cpp
        src/auth/salt.cpp
        src/key_exchange/MessageStructs.h
        src/auth/set_up_client.cpp
        src/auth/rotate_master_key/rotate_master_key.cpp
)

# Create main executable
add_executable(Eastwood
        src/main.cpp
        ${FRONTEND_SOURCES}
        ${DATABASE_SOURCES}
        ${CRYPTO_SOURCES}
        ${AUTH_SOURCES}
        ${qrcodegen_SOURCE_DIR}/cpp/qrcodegen.cpp
)

# I hope this works nially
if(APPLE)
    set_target_properties(Eastwood PROPERTIES
            MACOSX_BUNDLE TRUE
            MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist
            MACOSX_BUNDLE_ENTITLEMENTS ${CMAKE_CURRENT_SOURCE_DIR}/Eastwood.entitlements
    )
endif()

# Include directories and link libraries for main executable
target_include_directories(Eastwood PRIVATE
        ${SODIUM_INCLUDE_DIR}
        ${SQLCIPHER_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${Qt6Core_INCLUDE_DIRS}
        ${Qt6Gui_INCLUDE_DIRS}
        ${Qt6Widgets_INCLUDE_DIRS}
        ${Qt6UiTools_INCLUDE_DIRS}
        ${Qt6Svg_INCLUDE_DIRS}
        ${qrcodegen_SOURCE_DIR}/cpp
        ${OpenCV_INCLUDE_DIRS}
)

target_link_libraries(Eastwood PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::UiTools
        Qt6::Concurrent
        ${SODIUM_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        ${SQLCIPHER_LIBRARIES}
        ${OpenCV_LIBS}
)

# Create test executable
add_executable(EastwoodTests
        test/double_ratchet_test.cpp
        test/identity_session_test.cpp
        ${CRYPTO_SOURCES}
        src/database/database.cpp
        src/sessions/KeyBundle.h
        src/sessions/RatchetSessionManager.cpp
        src/keys/session_token_manager.h
        src/endpoints/endpoints.cpp
)

# Configure test target
target_include_directories(EastwoodTests PRIVATE
        ${SODIUM_INCLUDE_DIR}
        ${SQLCIPHER_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/key_exchange
        ${CMAKE_CURRENT_SOURCE_DIR}/src/sessions
        ${CMAKE_CURRENT_SOURCE_DIR}/src/keys
        ${CMAKE_CURRENT_SOURCE_DIR}/src/database
        ${CMAKE_CURRENT_SOURCE_DIR}/external/cereal/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/qrcodegen/cpp
)

# Link libraries using proper CMake targets
target_link_libraries(EastwoodTests PRIVATE
        gtest_main
        gtest
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::UiTools
        Qt6::Concurrent
        ${SODIUM_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        ${SQLCIPHER_LIBRARIES}
)

# Create integration test executable
add_executable(IntegrationTests
        test/integration_main_flow_test.cpp
        ${DATABASE_SOURCES}
        ${CRYPTO_SOURCES}
        ${AUTH_SOURCES}
)

target_include_directories(IntegrationTests PRIVATE
        ${SODIUM_INCLUDE_DIR}
        ${SQLCIPHER_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/external/cereal/include
)

target_link_libraries(IntegrationTests PRIVATE
        gtest_main
        gtest
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::UiTools
        Qt6::Concurrent
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
add_test(NAME IntegrationTests COMMAND IntegrationTests)

# Add tests to CTest
gtest_discover_tests(EastwoodTests)