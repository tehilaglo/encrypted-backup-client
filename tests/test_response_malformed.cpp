/**
 * @file test_response_malformed.cpp
 * @brief Unit tests for Response::deserialize()'s rejection of malformed wire buffers.
 *
 * @details
 * Covers empty buffers, headers/fields truncated at every field boundary
 * (user ID, AES key, encrypted file size, filename, checksum), payload sizes
 * that are declared smaller or larger than the actual bytes available, and two
 * currently-accepted edge cases: a zero-length AES-key section and trailing
 * bytes beyond the declared payload size, which deserialize() silently ignores.
 *
 * @author Tehila Cahnaman
 */

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "protocol/protocol_codes.h"
#include "protocol/response.h"
#include "protocol_test_helpers.h"
#include "utils/encoding_utils.h"

namespace
{
    constexpr version_t kVersion = 3;
    constexpr code_t kResponseCode = protocol::response::UPLOAD_RECEIVED;
    constexpr enc_chunk_size_t kEncryptedFileSize = 0x01020304;
    constexpr checksum_t kChecksum = 0xa1b2c3d4;

    const std::string kUserIdHex = "00112233445566778899aabbccddeeff";
    const std::vector<char> kAesKey{'k', 'e', 'y', '!'};

    /** @brief Builds one well-formed response payload shared by the truncation test cases below.*/
    std::vector<char> make_valid_payload()
    {
        const auto user_id = hex_string_to_byte_array<UNIQUE_ID_LEN>(kUserIdHex);
        return protocol_test::make_response_payload(
            user_id,
            kAesKey,
            kEncryptedFileSize,
            "backup.bin",
            kChecksum
        );
    }

    /** @brief Wraps make_valid_payload() with a matching header to form a complete, valid wire buffer.*/
    std::vector<char> make_valid_wire()
    {
        return protocol_test::make_response_wire(kVersion, kResponseCode, make_valid_payload());
    }

    /** @brief Builds a wire buffer whose payload is cut off after `payload_bytes_to_keep` bytes,
    while the header still declares the full payload size — simulating a truncated read.*/
    std::vector<char> make_truncated_wire(const std::size_t payload_bytes_to_keep)
    {
        auto wire = make_valid_wire();
        wire.resize(protocol_test::response::kHeaderSize + payload_bytes_to_keep);
        return wire;
    }
}

TEST_CASE("Response deserialization rejects empty buffer", "[response][deserialize][malformed]")
{
    REQUIRE_THROWS_AS(Response::deserialize({}), std::runtime_error);
}

TEST_CASE("Response deserialization rejects truncated header", "[response][deserialize][malformed]")
{
    std::vector<char> wire{static_cast<char>(kVersion)};
    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects missing response-code bytes", "[response][deserialize][malformed]")
{
    std::vector<char> wire{static_cast<char>(kVersion), static_cast<char>(0x00)};
    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects missing payload-size bytes", "[response][deserialize][malformed]")
{
    std::vector<char> wire{static_cast<char>(kVersion)};

    const auto response_code_bytes = protocol_test::network_bytes(static_cast<code_t>(protocol::response::ACK));
    wire.insert(wire.end(), response_code_bytes.begin(), response_code_bytes.end());

    wire.push_back(static_cast<char>(0x00));
    wire.push_back(static_cast<char>(0x00));

    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects declared payload smaller than fixed payload", "[response][deserialize][malformed]")
{
    constexpr payload_size_t too_small =
        static_cast<payload_size_t>(protocol_test::response::kFixedPayloadSize - 1U);

    const auto wire = protocol_test::make_response_wire(kVersion, protocol::response::FAILED, {}, too_small);

    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects declared payload larger than available bytes", "[response][deserialize][malformed]")
{
    const auto payload = make_valid_payload();
    const auto declared_size = static_cast<payload_size_t>(payload.size() + 10U);
    const auto wire = protocol_test::make_response_wire(kVersion, kResponseCode, payload, declared_size);

    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects truncated user ID bytes", "[response][deserialize][malformed]")
{
    const auto wire = make_truncated_wire(UNIQUE_ID_LEN - 1U);
    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects truncated AES-key section", "[response][deserialize][malformed]")
{
    const auto wire = make_truncated_wire(UNIQUE_ID_LEN + kAesKey.size() - 1U);
    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects truncated encrypted-file-size field", "[response][deserialize][malformed]")
{
    const auto wire = make_truncated_wire(
        UNIQUE_ID_LEN + kAesKey.size() + sizeof(enc_chunk_size_t) - 1U
    );
    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects truncated filename field", "[response][deserialize][malformed]")
{
    const auto wire = make_truncated_wire(
        UNIQUE_ID_LEN + kAesKey.size() + sizeof(enc_chunk_size_t) + FILE_NAME_LEN - 1U
    );
    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization rejects truncated checksum field", "[response][deserialize][malformed]")
{
    const auto wire = make_truncated_wire(
        UNIQUE_ID_LEN + kAesKey.size() + sizeof(enc_chunk_size_t) + FILE_NAME_LEN + sizeof(checksum_t) - 1U
    );
    REQUIRE_THROWS_AS(Response::deserialize(wire), std::runtime_error);
}

TEST_CASE("Response deserialization accepts zero-length AES-key section", "[response][deserialize][malformed]")
{
    const auto user_id = hex_string_to_byte_array<UNIQUE_ID_LEN>(kUserIdHex);
    const auto payload = protocol_test::make_response_payload(
        user_id,
        {},
        kEncryptedFileSize,
        "backup.bin",
        kChecksum
    );

    const auto wire = protocol_test::make_response_wire(kVersion, protocol::response::ACK, payload);
    const Response response = Response::deserialize(wire);

    REQUIRE(response.get_payload().get_encrypted_aes_key().empty());
}

TEST_CASE("Response deserialization currently ignores trailing bytes beyond declared payload", "[response][deserialize][malformed]")
{
    auto wire = make_valid_wire();
    wire.push_back(static_cast<char>(0x42));
    wire.push_back(static_cast<char>(0x43));

    const Response response = Response::deserialize(wire);

    REQUIRE(response.get_header().get_payload_size() == make_valid_payload().size());
    REQUIRE(response.get_payload().get_user_id() == kUserIdHex);
    REQUIRE(response.get_payload().get_encrypted_aes_key() == kAesKey);
    REQUIRE(response.get_payload().get_file_name() == "backup.bin");
}
