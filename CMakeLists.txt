cmake_minimum_required(VERSION 4.4)
project(quic_parsing)

set(CMAKE_CXX_STANDARD 23)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRYPTOPP REQUIRED IMPORTED_TARGET libcryptopp)


add_executable(quic_parsing main.cpp
        quic_packet.hpp
        encrypt.hpp
        encrypt.cpp
        quic_packet.cpp)

target_link_libraries(quic_parsing PRIVATE PkgConfig::CRYPTOPP)