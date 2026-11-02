//
// Created by klewy on 11/3/26.
//

#include "encrypt.hpp"

#include <span>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

std::vector<std::uint8_t> hkdf_extract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> keyring) {
    std::vector<std::uint8_t> digest(CryptoPP::SHA256::DIGESTSIZE, 0);

    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    hmac.SetKey(salt.data(), salt.size());
    hmac.CalculateDigest(digest.data(), keyring.data(), keyring.size());

    return digest;
}

std::vector<std::uint8_t> hkdf_expand(std::span<const std::uint8_t> prk, std::span<const std::uint8_t> info,
                                      const std::uint16_t length) {
    constexpr std::size_t hash_len = CryptoPP::SHA256::DIGESTSIZE;
    if (length > 255 * hash_len) {
        throw std::length_error("hkdf_expand: length too large");
    }

    CryptoPP::HMAC<CryptoPP::SHA256> hmac(prk.data(), prk.size());

    std::vector<std::uint8_t> okm;
    okm.reserve(length);

    std::array<std::uint8_t, hash_len> t{};
    std::size_t t_len = 0; // T(0) is empty

    for (std::uint8_t i = 1; okm.size() < length; ++i) {
        hmac.Update(t.data(), t_len);
        hmac.Update(info.data(), info.size());
        hmac.Update(&i, 1);
        hmac.Final(t.data()); // also resets the HMAC state, key is kept
        t_len = hash_len;

        const std::size_t take = std::min<std::size_t>(hash_len, length - okm.size());
        okm.insert(okm.end(), t.begin(), t.begin() + take);
    }
    return okm;
}


std::vector<std::uint8_t> hkdf_expand_label(std::span<const std::uint8_t> secret, const std::string_view label,
                                            std::span<const std::uint8_t> context, const std::uint16_t length) {
    std::string full_label = "tls13 " + std::string{label};

    std::vector<std::uint8_t> info;
    info.reserve(2 + full_label.size() + 0);
    info.push_back(static_cast<std::uint8_t>(length >> 8));
    info.push_back(static_cast<std::uint8_t>(length & 0xFF));
    info.push_back(static_cast<std::uint8_t>(full_label.size()));
    info.insert(info.end(), full_label.begin(), full_label.end());
    info.push_back(static_cast<std::uint8_t>(context.size()));
    info.insert(info.end(), context.begin(), context.end());

    return hkdf_expand(secret, info, length);
}

std::vector<std::uint8_t>
header_protection(std::span<const std::uint8_t> hp_key, std::span<const std::uint8_t> sample) {
    std::array<std::uint8_t, 16> mask{};

    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption aes;
    aes.SetKey(hp_key.data(), hp_key.size());
    aes.ProcessData(mask.data(), sample.data(), sample.size());

    return {mask.data(), mask.data() + mask.size()};
}
