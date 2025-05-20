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

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

add_executable(Eastwood main.cpp)
target_include_directories(Eastwood PRIVATE ${CRYPTOPP_INCLUDE_DIR})
target_link_libraries(Eastwood PRIVATE 
    Qt6::Widgets
    ${CRYPTOPP_LIBRARY}
)

