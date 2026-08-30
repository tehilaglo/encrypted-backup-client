#include <array>
#include <cstdint>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "protocol/protocol_codes.h"
#include "protocol/request.h"
#include "protocol_test_helpers.h"
#include "utils/encoding_utils.h"

TEST_CASE("Request serialization keeps default version and zero-initialized fields", "[request][serialize]")
{
    Request request;

    const auto serialized = request.serialize();

    REQUIRE(request.get_header().get_version() == 3);
    REQUIRE(serialized.size() == protocol_test::request::kHeaderSize + protocol_test::request::kFixedPayloadSize);

    for (std::size_t index = 0; index < serialized.size(); ++index)
    {
        const auto byte = static_cast<std::uint8_t>(serialized[index]);
        if (index == protocol_test::request::kOffsetVersion)
        {
            REQUIRE(byte == 3U);
        }
        else
        {
            REQUIRE(byte == 0U);
        }
    }
}

TEST_CASE("Request serialization layout matches protocol field order", "[request][serialize][layout]")
{
    Request request;

    constexpr code_t request_code = 0x1234;
    constexpr payload_size_t payload_size = 0x01020304;
    constexpr enc_chunk_size_t encrypted_chunk_size = 0x0a0b0c0d;
    constexpr file_size_t file_size = 0x11223344;
    constexpr packet_num_t packet_number = 0x5566;
    constexpr total_packets_t total_packets = 0x7788;

    const std::string user_id_hex = "00112233445566778899aabbccddeeff";
    const auto user_id = hex_string_to_byte_array<UNIQUE_ID_LEN>(user_id_hex);

    std::array<char, RSA_KEY_LEN> public_key{};
    for (std::size_t index = 0; index < public_key.size(); ++index)
    {
        public_key[index] = static_cast<char>((index + 1) & 0xff);
    }

    const std::vector<char> encrypted_chunk_data{
        static_cast<char>(0x41),
        static_cast<char>(0x00),
        static_cast<char>(0x5a)
    };

    request.get_header().set_user_id(user_id_hex);
    request.get_header().set_request_code(request_code);
    request.get_header().set_payload_size(payload_size);

    request.get_payload().set_username("alice");
    request.get_payload().set_public_key(public_key.data());
    request.get_payload().set_encrypted_chunk_size(encrypted_chunk_size);
    request.get_payload().set_file_size(file_size);
    request.get_payload().set_packet_number(packet_number);
    request.get_payload().set_total_packets(total_packets);
    request.get_payload().set_file_name("report.bin");
    request.get_payload().set_encrypted_chunk_data(encrypted_chunk_data);

    const auto serialized = request.serialize();

    REQUIRE(serialized.size()
            == protocol_test::request::kHeaderSize + protocol_test::request::kFixedPayloadSize + encrypted_chunk_data.size());

    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetUserId, UNIQUE_ID_LEN)
            == protocol_test::to_vector(user_id));

    REQUIRE(static_cast<std::uint8_t>(serialized[protocol_test::request::kOffsetVersion]) == 3U);

    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetRequestCode, sizeof(code_t))
            == protocol_test::to_vector(protocol_test::host_bytes(request_code)));

    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetPayloadSize, sizeof(payload_size_t))
            == protocol_test::to_vector(protocol_test::host_bytes(payload_size)));

    const auto expected_username = protocol_test::make_fixed_c_string_field<USERNAME_LEN>("alice");
    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetUsername, USERNAME_LEN)
            == protocol_test::to_vector(expected_username));

    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetPublicKey, RSA_KEY_LEN)
            == std::vector<char>(public_key.begin(), public_key.end()));

    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetEncryptedChunkSize, sizeof(enc_chunk_size_t))
            == protocol_test::to_vector(protocol_test::host_bytes(encrypted_chunk_size)));

    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetFileSize, sizeof(file_size_t))
            == protocol_test::to_vector(protocol_test::host_bytes(file_size)));

    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetPacketNumber, sizeof(packet_num_t))
            == protocol_test::to_vector(protocol_test::host_bytes(packet_number)));

    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetTotalPackets, sizeof(total_packets_t))
            == protocol_test::to_vector(protocol_test::host_bytes(total_packets)));

    const auto expected_file_name = protocol_test::make_fixed_c_string_field<FILE_NAME_LEN>("report.bin");
    REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetFileName, FILE_NAME_LEN)
            == protocol_test::to_vector(expected_file_name));

    REQUIRE(protocol_test::slice(
                serialized,
                protocol_test::request::kOffsetEncryptedChunkData,
                encrypted_chunk_data.size())
            == encrypted_chunk_data);
}

TEST_CASE("Request serialization numeric fields are currently host-endian", "[request][serialize][endianness]")
{
    Request request;

    constexpr code_t request_code = 0x1234;
    constexpr payload_size_t payload_size = 0x01020304;
    constexpr file_size_t file_size = 0x11223344;
    constexpr packet_num_t packet_number = 0x5566;

    request.get_header().set_request_code(request_code);
    request.get_header().set_payload_size(payload_size);
    request.get_payload().set_file_size(file_size);
    request.get_payload().set_packet_number(packet_number);

    const auto serialized = request.serialize();

    const auto request_code_wire =
        protocol_test::slice(serialized, protocol_test::request::kOffsetRequestCode, sizeof(code_t));

    const auto payload_size_wire =
        protocol_test::slice(serialized, protocol_test::request::kOffsetPayloadSize, sizeof(payload_size_t));

    const auto file_size_wire =
        protocol_test::slice(serialized, protocol_test::request::kOffsetFileSize, sizeof(file_size_t));

    const auto packet_number_wire =
        protocol_test::slice(serialized, protocol_test::request::kOffsetPacketNumber, sizeof(packet_num_t));

    REQUIRE(request_code_wire == protocol_test::to_vector(protocol_test::host_bytes(request_code)));
    REQUIRE(payload_size_wire == protocol_test::to_vector(protocol_test::host_bytes(payload_size)));
    REQUIRE(file_size_wire == protocol_test::to_vector(protocol_test::host_bytes(file_size)));
    REQUIRE(packet_number_wire == protocol_test::to_vector(protocol_test::host_bytes(packet_number)));

    if (protocol_test::is_little_endian_host())
    {
        REQUIRE(request_code_wire != protocol_test::to_vector(protocol_test::network_bytes(request_code)));
        REQUIRE(payload_size_wire != protocol_test::to_vector(protocol_test::network_bytes(payload_size)));
        REQUIRE(file_size_wire != protocol_test::to_vector(protocol_test::network_bytes(file_size)));
        REQUIRE(packet_number_wire != protocol_test::to_vector(protocol_test::network_bytes(packet_number)));
    }
    else
    {
        REQUIRE(request_code_wire == protocol_test::to_vector(protocol_test::network_bytes(request_code)));
        REQUIRE(payload_size_wire == protocol_test::to_vector(protocol_test::network_bytes(payload_size)));
        REQUIRE(file_size_wire == protocol_test::to_vector(protocol_test::network_bytes(file_size)));
        REQUIRE(packet_number_wire == protocol_test::to_vector(protocol_test::network_bytes(packet_number)));
    }
}
