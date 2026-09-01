/**
 * @file protocol_test_helpers.h
 * @brief Shared helpers for building and inspecting protocol wire bytes in tests.
 *
 * @details
 * Centralizes the byte-layout knowledge (field offsets and sizes) that would
 * otherwise be duplicated across the protocol test files. Provides:
 *  - Field offset/size constants mirroring the Request and Response wire layouts.
 *  - Endianness helpers for producing host-order and network-order byte sequences.
 *  - Builders for fixed-width C-string fields and complete response payload/wire buffers.
 *
 * These helpers only assemble or slice raw bytes; they do not call the production
 * Request/Response (de)serialization code, so tests built on them stay independent
 * of the implementation under test.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <arpa/inet.h>

#include "protocol/protocol_types.h"

namespace protocol_test
{
    /** Byte-layout constants mirroring Request's wire format (see protocol/request.h).*/
    namespace request
    {
        inline constexpr std::size_t kHeaderSize =
            UNIQUE_ID_LEN + sizeof(version_t) + sizeof(code_t) + sizeof(payload_size_t);

        inline constexpr std::size_t kFixedPayloadSize =
            USERNAME_LEN
            + RSA_KEY_LEN
            + sizeof(enc_chunk_size_t)
            + sizeof(file_size_t)
            + sizeof(packet_num_t)
            + sizeof(total_packets_t)
            + FILE_NAME_LEN;

        inline constexpr std::size_t kOffsetUserId = 0;
        inline constexpr std::size_t kOffsetVersion = kOffsetUserId + UNIQUE_ID_LEN;
        inline constexpr std::size_t kOffsetRequestCode = kOffsetVersion + sizeof(version_t);
        inline constexpr std::size_t kOffsetPayloadSize = kOffsetRequestCode + sizeof(code_t);
        inline constexpr std::size_t kOffsetUsername = kHeaderSize;
        inline constexpr std::size_t kOffsetPublicKey = kOffsetUsername + USERNAME_LEN;
        inline constexpr std::size_t kOffsetEncryptedChunkSize = kOffsetPublicKey + RSA_KEY_LEN;
        inline constexpr std::size_t kOffsetFileSize = kOffsetEncryptedChunkSize + sizeof(enc_chunk_size_t);
        inline constexpr std::size_t kOffsetPacketNumber = kOffsetFileSize + sizeof(file_size_t);
        inline constexpr std::size_t kOffsetTotalPackets = kOffsetPacketNumber + sizeof(packet_num_t);
        inline constexpr std::size_t kOffsetFileName = kOffsetTotalPackets + sizeof(total_packets_t);
        inline constexpr std::size_t kOffsetEncryptedChunkData = kOffsetFileName + FILE_NAME_LEN;
    }

    /** Byte-layout constants mirroring Response's wire format (see protocol/response.h).*/
    namespace response
    {
        inline constexpr std::size_t kHeaderSize =
            sizeof(version_t) + sizeof(code_t) + sizeof(payload_size_t);

        inline constexpr std::size_t kFixedPayloadSize =
            UNIQUE_ID_LEN + sizeof(enc_chunk_size_t) + FILE_NAME_LEN + sizeof(checksum_t);
    }

    /** @brief Reports whether the current host stores multi-byte integers little-endian first.*/
    inline bool is_little_endian_host()
    {
        const std::uint16_t one = 1;
        return *reinterpret_cast<const std::uint8_t*>(&one) == 1;
    }

    /** @brief Returns the raw in-memory (host-endian) byte representation of an integral value.*/
    template <typename T>
    std::array<char, sizeof(T)> host_bytes(const T value)
    {
        std::array<char, sizeof(T)> bytes{};
        std::memcpy(bytes.data(), &value, sizeof(T));
        return bytes;
    }

    /** @brief Returns the big-endian ("network order") byte representation of a 16- or 32-bit integer.*/
    template <typename T>
    std::array<char, sizeof(T)> network_bytes(const T value)
    {
        std::array<char, sizeof(T)> bytes{};

        if constexpr (sizeof(T) == sizeof(std::uint16_t))
        {
            const auto network_value = htons(static_cast<std::uint16_t>(value));
            std::memcpy(bytes.data(), &network_value, sizeof(network_value));
        }
        else if constexpr (sizeof(T) == sizeof(std::uint32_t))
        {
            const auto network_value = htonl(static_cast<std::uint32_t>(value));
            std::memcpy(bytes.data(), &network_value, sizeof(network_value));
        }
        else
        {
            static_assert(sizeof(T) == sizeof(std::uint16_t) || sizeof(T) == sizeof(std::uint32_t),
                          "network_bytes supports only 16-bit and 32-bit integers");
        }

        return bytes;
    }

    /** @brief Converts a fixed-size byte array into a vector, for comparison against sliced wire bytes.*/
    template <std::size_t N>
    std::vector<char> to_vector(const std::array<char, N>& values)
    {
        return {values.begin(), values.end()};
    }

    /** @brief Extracts the byte range `[offset, offset + size)` from a wire buffer.*/
    inline std::vector<char> slice(const std::vector<char>& data, const std::size_t offset, const std::size_t size)
    {
        return {data.begin() + static_cast<std::ptrdiff_t>(offset),
                data.begin() + static_cast<std::ptrdiff_t>(offset + size)};
    }

    /** @brief Builds a fixed-width, null-padded C-string field, matching the protocol's
    username/filename truncation behavior (value truncated to `N - 1` bytes, always null-terminated).*/
    template <std::size_t N>
    std::array<char, N> make_fixed_c_string_field(const std::string& value)
    {
        static_assert(N > 0, "fixed-width protocol string must be at least 1 byte");

        std::array<char, N> field{};
        field.fill('\0');

        const std::size_t copy_len = std::min(value.size(), static_cast<std::size_t>(N - 1));
        std::copy_n(value.begin(), copy_len, field.begin());

        return field;
    }

    /** @brief Appends `value` to `output` in network byte order.*/
    template <typename T>
    void append_network_field(std::vector<char>& output, const T value)
    {
        const auto bytes = network_bytes(value);
        output.insert(output.end(), bytes.begin(), bytes.end());
    }

    /** @brief Assembles a Response payload's fixed fields in wire order: user ID,
    encrypted AES key, encrypted file size, fixed-width filename, then checksum.*/
    inline std::vector<char> make_response_payload(
        const std::array<char, UNIQUE_ID_LEN>& user_id,
        const std::vector<char>& encrypted_aes_key,
        const enc_chunk_size_t encrypted_file_size,
        const std::string& file_name,
        const checksum_t checksum
    )
    {
        std::vector<char> payload;
        payload.reserve(
            UNIQUE_ID_LEN
            + encrypted_aes_key.size()
            + sizeof(enc_chunk_size_t)
            + FILE_NAME_LEN
            + sizeof(checksum_t)
        );

        payload.insert(payload.end(), user_id.begin(), user_id.end());
        payload.insert(payload.end(), encrypted_aes_key.begin(), encrypted_aes_key.end());
        append_network_field(payload, encrypted_file_size);

        const auto file_name_field = make_fixed_c_string_field<FILE_NAME_LEN>(file_name);
        payload.insert(payload.end(), file_name_field.begin(), file_name_field.end());

        append_network_field(payload, checksum);

        return payload;
    }

    /** @brief Wraps a payload with a Response header (version, code, declared payload
    size) to form a complete wire buffer. `declared_payload_size` defaults to the
    payload's actual size, but can be overridden to construct malformed inputs.*/
    inline std::vector<char> make_response_wire(
        const version_t version,
        const code_t response_code,
        const std::vector<char>& payload,
        const std::optional<payload_size_t> declared_payload_size = std::nullopt
    )
    {
        std::vector<char> wire;
        wire.reserve(response::kHeaderSize + payload.size());

        wire.push_back(static_cast<char>(version));
        append_network_field(wire, response_code);

        const auto payload_size = declared_payload_size.value_or(static_cast<payload_size_t>(payload.size()));
        append_network_field(wire, payload_size);

        wire.insert(wire.end(), payload.begin(), payload.end());
        return wire;
    }
}
