//
// Created by klewy on 11/3/26.
//

#ifndef QUIC_PARSING_ENCRYPT_HPP
#define QUIC_PARSING_ENCRYPT_HPP

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

constexpr std::array<std::uint8_t, 20> initial_salt = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

std::vector<std::uint8_t> hkdf_extract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> keyring);
std::vector<std::uint8_t> hkdf_expand(std::span<const std::uint8_t> prk, std::span<const std::uint8_t> info, const std::uint16_t length);
std::vector<std::uint8_t> hkdf_expand_label(std::span <const std::uint8_t> secret, const std::string_view label, std::span<const std::uint8_t> context, const std::uint16_t length);

std::vector<std::uint8_t> header_protection(std::span<const std::uint8_t> hp_key, std::span<const std::uint8_t> sample);

#endif //QUIC_PARSING_ENCRYPT_HPP
