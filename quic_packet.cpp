//
// Created by klewy on 11/3/26.
//

#include "quic_packet.hpp"

#include <bitset>
#include <cassert>
#include <cstring>
#include <print>
#include <netinet/in.h>

std::vector<std::uint8_t> get_client_dst_conn(std::span<const std::uint8_t> quic) {
    std::vector<std::uint8_t> dst_conn;

    quic = quic.subspan(1 + 4);

    const std::uint8_t dest_conn_len = quic.front();
    dst_conn.resize(static_cast<std::uint8_t>(dest_conn_len));

    quic = quic.subspan(sizeof(dest_conn_len));
    std::memcpy(dst_conn.data(), quic.data(), dst_conn.size());

    return dst_conn;
}

std::uint32_t get_packet_number(std::span<const std::uint8_t> quic) {
    auto s = quic;

    auto need = [&s](std::size_t n) {
        if (s.size() < n) throw std::out_of_range("get_packet_number: truncated packet");
    };
    auto skip = [&](std::size_t n) {
        need(n);
        s = s.subspan(n);
    };
    auto varint = [&]() -> std::uint64_t {
        need(1);
        const std::size_t len = std::size_t{1} << (s[0] >> 6);
        need(len);
        std::uint64_t v = s[0] & 0x3f;
        for (std::size_t i = 1; i < len; ++i) v = (v << 8) | s[i];
        s = s.subspan(len);
        return v;
    };

    skip(1 + 4);                 // first byte + version
    need(1); skip(1 + s[0]);     // DCID len + DCID
    need(1); skip(1 + s[0]);     // SCID len + SCID
    skip(varint());              // token length + token
    varint();                    // Length

    const std::size_t pn_length = (quic[0] & 0x03) + 1;
    need(pn_length);

    std::uint32_t pn = 0;
    for (std::size_t i = 0; i < pn_length; ++i) {
        pn = (pn << 8) | s[i];
    }
    return pn;
}

std::size_t get_pn_offset(std::span<const std::uint8_t> quic) {
    std::span<const std::uint8_t> span{quic};
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

    return std::distance(quic.data(), span.data());
}

std::size_t get_payload_offset(std::span<const std::uint8_t> quic) {
    const std::uint8_t pn_length = (quic[0] & 0x03) + 1;
    const auto pn_offset = get_pn_offset(quic);

    return pn_offset + pn_length;
}

namespace {

std::optional<std::uint64_t> read_varint(std::span<const std::uint8_t>& s) {
    if (s.empty()) return std::nullopt;
    const std::size_t len = std::size_t{1} << (s[0] >> 6);
    if (s.size() < len) return std::nullopt;
    std::uint64_t v = s[0] & 0x3f;
    for (std::size_t i = 1; i < len; ++i) v = (v << 8) | s[i];
    s = s.subspan(len);
    return v;
}

void print_hex(const char* name, std::span<const std::uint8_t> b) {
    std::print("{} ({}): ", name, b.size());
    for (auto x : b) std::print("{:02x}", x);
    std::println();
}

} // namespace

void print_long_header(std::span<const std::uint8_t> packet) {
    auto s = packet;

    auto take = [&s](std::size_t n) -> std::optional<std::span<const std::uint8_t>> {
        if (s.size() < n) return std::nullopt;
        auto r = s.first(n);
        s = s.subspan(n);
        return r;
    };

    auto fb = take(1);
    auto ver = take(4);
    if (!fb || !ver) { std::println("truncated: first byte/version"); return; }

    const std::uint8_t first = (*fb)[0];
    const std::uint32_t version = (std::uint32_t{(*ver)[0]} << 24) | (std::uint32_t{(*ver)[1]} << 16) |
                                  (std::uint32_t{(*ver)[2]} << 8) | (*ver)[3];

    static constexpr const char* types[] = {"Initial", "0-RTT", "Handshake", "Retry"};
    const unsigned type = (first >> 4) & 0x03;

    std::println("first byte: {:02x}", first);
    std::println("  header form: {} (must be 1)", first >> 7);
    std::println("  fixed bit:   {} (must be 1)", (first >> 6) & 1);
    std::println("  type:        {}", types[type]);
    std::println("  reserved:    {} (must be 0)", (first >> 2) & 0x03);
    std::println("  pn_length:   {}", (first & 0x03) + 1);
    std::println("version: {:08x}", version);

    auto dcid_len = take(1);
    if (!dcid_len) { std::println("truncated: dcid len"); return; }
    auto dcid = take((*dcid_len)[0]);
    if (!dcid) { std::println("truncated: dcid"); return; }
    print_hex("dcid", *dcid);

    auto scid_len = take(1);
    if (!scid_len) { std::println("truncated: scid len"); return; }
    auto scid = take((*scid_len)[0]);
    if (!scid) { std::println("truncated: scid"); return; }
    print_hex("scid", *scid);

    if (type == 3) { // Retry: retry token + 16-byte integrity tag, no length/pn
        print_hex("retry token + integrity tag", s);
        return;
    }

    if (type == 0) { // Initial only
        auto token_len = read_varint(s);
        if (!token_len) { std::println("truncated: token len"); return; }
        auto token = take(*token_len);
        if (!token) { std::println("truncated: token"); return; }
        print_hex("token", *token);
    }

    auto length = read_varint(s);
    if (!length) { std::println("truncated: length"); return; }

    const std::size_t pn_offset = packet.size() - s.size();
    const std::size_t pn_len = (first & 0x03) + 1;
    std::println("length: {} (pn + payload + tag)", *length);
    std::println("pn_offset: {}", pn_offset);

    if (*length > s.size()) std::println("warning: length exceeds remaining bytes ({})", s.size());

    auto pn = take(pn_len);
    if (!pn) { std::println("truncated: packet number"); return; }
    print_hex("packet number", *pn);
}


void parse_payload(std::span<const std::uint8_t> packet) {
    const auto pl_off = get_payload_offset(packet);

    std::span<const std::uint8_t> payload = packet.subspan(pl_off);

    const auto frame_type = payload.front();
    if (frame_type == 0x06) {
        std::println("crypto frame");
        payload = payload.subspan(1);

        const auto offset = read_varint(payload).value();
        std::println("off: {}", offset);

        const auto len = read_varint(payload).value();
        std::println("len: {}", len);
    }
}
