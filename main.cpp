#include <bitset>
#include <cassert>
#include <iostream>
#include <cstring>
#include <print>
#include <ranges>
#include "quic_packet.hpp"
#include <linux/udp.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <vector>
#include "encrypt.hpp"


std::vector<std::uint8_t> lift_header_prot(std::span<const std::uint8_t> packet) {
    // 128-bit AES in Electronic Codebook (ECB) mode
    std::vector<std::uint8_t> quic{packet.begin(), packet.end()};

    std::size_t pn_offset = 0;
    {
        std::span<const std::uint8_t> span{packet};
        span = span.subspan(1 + 4);

        const std::uint8_t dest_id_len = span.front();
        span = span.subspan(dest_id_len + sizeof(dest_id_len));

        const std::uint8_t conn_id_len = span.front();
        span = span.subspan(conn_id_len + sizeof(conn_id_len));

        const std::uint8_t token_len = span.front();
        assert(token_len == 0);
        span = span.subspan(token_len + sizeof(token_len));

        const std::uint8_t len_byte = span.front();
        const auto len_len = 1 << (len_byte >> 6);

        span = span.subspan(len_len);

        pn_offset = std::distance(packet.data(), span.data());
    }

    {
        constexpr std::array<const std::uint8_t, 20> initial_salt = {
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        };

        const auto dest_conn = get_client_dst_conn(packet);
        const auto init_secret = hkdf_extract(initial_salt, dest_conn);
        const auto client_init_secret = hkdf_expand_label(init_secret, "client in", {}, 32);
        const auto hp_key = hkdf_expand_label(client_init_secret, "quic hp", {}, 16);

        const auto sample = packet.subspan(pn_offset + 4).first(16);
        const auto mask = header_protection(hp_key, sample);

        quic[0] ^= mask[0] & 0x0f;
        const std::uint8_t pn_length = (quic[0] & 0x03) + 1;
        for (std::size_t i = 0; i < pn_length; ++i) {
            quic[pn_offset + i] ^= mask[1 + i];
        }
    }
    return quic;
}

std::vector<std::uint8_t> lift_packet_prot(std::span<const std::uint8_t> packet) {
    std::vector<std::uint8_t> quic{packet.begin(), packet.end()};

    const auto dest_conn = get_client_dst_conn(packet);
    const auto init_secret = hkdf_extract(initial_salt, dest_conn);
    const auto client_init_secret = hkdf_expand_label(init_secret, "client in", {}, 32);

    const auto iv_secret = hkdf_expand_label(client_init_secret, "quic iv", {}, 12); // 12 because MIN nonce is 12 bytes in AES-GCM
    const auto aes_key = hkdf_expand_label(client_init_secret, "quic key", {}, 16);

    std::vector<std::uint8_t> nonce(iv_secret.size(), 0);
    {
        const std::uint64_t packet_num = get_packet_number(quic);
        std::memcpy(nonce.data() + nonce.size() - sizeof(packet_num), &packet_num, sizeof(packet_num));
        for (auto i = 0; i < nonce.size(); ++i) {
            nonce[i] ^= iv_secret[i];
        }
    }

    const std::uint8_t pn_length = (quic[0] & 0x03) + 1;
    const auto after_pn_offset = get_pn_offset(quic) + pn_length;

    std::span<const std::uint8_t> header{quic.begin(), quic.begin() + static_cast<std::ptrdiff_t>(after_pn_offset)};
    std::span<const std::uint8_t> ciphertext{quic.begin() + static_cast<std::ptrdiff_t>(after_pn_offset), quic.end()};

    const auto plaintext = aead(aes_key, nonce, header, ciphertext);
    std::println("off: {}, size: {}", after_pn_offset, quic.size());
    quic.erase(quic.begin() + static_cast<std::ptrdiff_t>(after_pn_offset), quic.end());
    quic.insert(quic.end(), plaintext.begin(), plaintext.end());

    return quic;
}

// aaabbccc

bool try_long_header(std::span<const std::uint8_t> packet) {
    const std::uint8_t first_b = packet.front();

    if (first_b & 0x80 == 0) {
        return false; // not long header
    }

    if (first_b & 0x40 == 0) {
        return false; // fixed bit not set
    }

    packet = packet.subspan(1);

    if (packet.size() < 4) {
        std::println(std::cerr, "Malformed packet");
        return false;
    }

    std::uint32_t version = 0;
    std::memcpy(&version, packet.data(), sizeof(version));
    version = ntohl(version);

    if (version != 0x00000001) {
        std::println(std::cerr, "Not QUIC ver. 1");
        return false;
    }

    return true;
}


void parse_quic(std::span<const std::uint8_t> packet) {
    {
        const auto* iph = reinterpret_cast<const iphdr*>(packet.data());
        packet = packet.subspan(iph->ihl * 4);
    }

    const auto* udph = reinterpret_cast<const udphdr*>(packet.data());
    std::println("Source port: {}, Dest. port: {}", ntohs(udph->source), ntohs(udph->dest));
    packet = packet.subspan(sizeof(udphdr));

    {
        // long header
        const auto is_long_hdr = try_long_header(packet);

        const auto packet_type = (packet.front() & 0x30) >> 4;
        if (packet_type != 0x00) {
            std::println(std::cerr, "Packet is not Initial");
            return;
        }

        auto decrypted_packet = lift_header_prot(packet);
        print_long_header(decrypted_packet);

        decrypted_packet = lift_packet_prot(decrypted_packet);

        parse_payload(decrypted_packet);
    }
}


int main() {
    parse_quic(quic_packet);
}