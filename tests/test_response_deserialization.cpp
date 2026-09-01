/**
 * @file test_response_deserialization.cpp
 * @brief Unit tests for Response::deserialize() on well-formed wire buffers.
 *
 * @details
 * Confirms that a fully populated response wire buffer (built via
 * protocol_test_helpers) round-trips through Response::deserialize() into the
 * expected header and payload fields, including the edge case of a zero-length
 * encrypted AES key section.
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

TEST_CASE("Response deserialization parses all protocol payload fields", "[response][deserialize]")
{
    constexpr version_t version = 3;
    constexpr code_t response_code = protocol::response::UPLOAD_RECEIVED;
    constexpr enc_chunk_size_t encrypted_file_size = 0x11223344;
    constexpr checksum_t checksum = 0xa1b2c3d4;

    const std::string user_id_hex = "00112233445566778899aabbccddeeff";
    const auto user_id = hex_string_to_byte_array<UNIQUE_ID_LEN>(user_id_hex);

    const std::vector<char> encrypted_aes_key{
        static_cast<char>(0x10),
        static_cast<char>(0x00),
        static_cast<char>(0x7f),
        static_cast<char>(0x80)
    };

    const auto payload = protocol_test::make_response_payload(
        user_id,
        encrypted_aes_key,
        encrypted_file_size,
        "backup.bin",
        checksum
    );

    const auto wire = protocol_test::make_response_wire(version, response_code, payload);
    const Response response = Response::deserialize(wire);

    REQUIRE(response.get_header().get_version() == version);
    REQUIRE(response.get_header().get_response_code() == response_code);
    REQUIRE(response.get_header().get_payload_size() == payload.size());

    REQUIRE(response.get_payload().get_user_id() == user_id_hex);
    REQUIRE(response.get_payload().get_encrypted_aes_key() == encrypted_aes_key);
    REQUIRE(response.get_payload().get_encrypted_file_size() == encrypted_file_size);
    REQUIRE(response.get_payload().get_file_name() == "backup.bin");
    REQUIRE(response.get_payload().get_checksum() == checksum);
}

TEST_CASE("Response deserialization allows zero-length AES key payload section", "[response][deserialize]")
{
    constexpr version_t version = 3;
    constexpr code_t response_code = protocol::response::ACK;
    constexpr enc_chunk_size_t encrypted_file_size = 0x01020304;
    constexpr checksum_t checksum = 0x55667788;

    const auto user_id = hex_string_to_byte_array<UNIQUE_ID_LEN>(
        "ffeeddccbbaa99887766554433221100"
    );

    const auto payload = protocol_test::make_response_payload(
        user_id,
        {},
        encrypted_file_size,
        "no-key.bin",
        checksum
    );

    const auto wire = protocol_test::make_response_wire(version, response_code, payload);
    const Response response = Response::deserialize(wire);

    REQUIRE(response.get_header().get_payload_size() == payload.size());
    REQUIRE(response.get_payload().get_encrypted_aes_key().empty());
    REQUIRE(response.get_payload().get_encrypted_file_size() == encrypted_file_size);
    REQUIRE(response.get_payload().get_file_name() == "no-key.bin");
    REQUIRE(response.get_payload().get_checksum() == checksum);
}
