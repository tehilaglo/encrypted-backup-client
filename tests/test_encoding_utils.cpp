#include <array>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "protocol/protocol_types.h"
#include "utils/encoding_utils.h"

TEST_CASE("User ID bytes round-trip between binary and hex", "[encoding][hex]")
{
    const std::array<char, UNIQUE_ID_LEN> user_id{
        static_cast<char>(0x00), static_cast<char>(0x01), static_cast<char>(0x02), static_cast<char>(0x03),
        static_cast<char>(0x7f), static_cast<char>(0x80), static_cast<char>(0x81), static_cast<char>(0xff),
        static_cast<char>(0x10), static_cast<char>(0x20), static_cast<char>(0x30), static_cast<char>(0x40),
        static_cast<char>(0x50), static_cast<char>(0x60), static_cast<char>(0x70), static_cast<char>(0x90)
    };

    const auto hex = bytes_to_hex(user_id.data(), user_id.size());
    const auto decoded = hex_string_to_byte_array<UNIQUE_ID_LEN>(hex);

    REQUIRE(decoded == user_id);
}

TEST_CASE("bytes_to_hex preserves zeros and high-bit bytes", "[encoding][hex]")
{
    const std::array<char, UNIQUE_ID_LEN> zeros{};
    REQUIRE(bytes_to_hex(zeros.data(), zeros.size()) == std::string(UNIQUE_ID_LEN * 2, '0'));

    const std::array<char, 5> bytes{
        static_cast<char>(0x00),
        static_cast<char>(0x7f),
        static_cast<char>(0x80),
        static_cast<char>(0xfe),
        static_cast<char>(0xff)
    };
    REQUIRE(bytes_to_hex(bytes.data(), bytes.size()) == "007f80feff");
}

TEST_CASE("hex_string_to_byte_array accepts mixed uppercase and lowercase hex", "[encoding][hex]")
{
    const auto decoded = hex_string_to_byte_array<4>("A1b2C3d4");

    REQUIRE(static_cast<unsigned char>(decoded[0]) == 0xa1U);
    REQUIRE(static_cast<unsigned char>(decoded[1]) == 0xb2U);
    REQUIRE(static_cast<unsigned char>(decoded[2]) == 0xc3U);
    REQUIRE(static_cast<unsigned char>(decoded[3]) == 0xd4U);
}

TEST_CASE("hex_string_to_byte_array rejects invalid hex length", "[encoding][hex]")
{
    REQUIRE_THROWS_AS(hex_string_to_byte_array<4>("0011aa"), std::invalid_argument);
}

TEST_CASE("hex_string_to_byte_array rejects malformed characters", "[encoding][hex]")
{
    REQUIRE_THROWS_AS(hex_string_to_byte_array<4>("0011zz99"), std::invalid_argument);
}

TEST_CASE("bytes_to_hex validates null input pointer", "[encoding][hex]")
{
    REQUIRE(bytes_to_hex(nullptr, 0).empty());
    REQUIRE_THROWS_AS(bytes_to_hex(nullptr, 1), std::invalid_argument);
}
