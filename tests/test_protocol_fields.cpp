#include <string>
#include <type_traits>

#include <catch2/catch_test_macros.hpp>

#include "protocol/request.h"
#include "protocol/response.h"
#include "protocol_test_helpers.h"

static_assert(UNIQUE_ID_LEN == 16, "UNIQUE_ID_LEN must remain 16 bytes");
static_assert(RSA_KEY_LEN == 160, "RSA_KEY_LEN must remain 160 bytes");
static_assert(USERNAME_LEN == 64, "USERNAME_LEN must remain 64 bytes");
static_assert(FILE_NAME_LEN == 255, "FILE_NAME_LEN must remain 255 bytes");

static_assert(sizeof(version_t) == 1, "version_t must remain 1 byte");
static_assert(sizeof(code_t) == 2, "code_t must remain 2 bytes");
static_assert(sizeof(payload_size_t) == 4, "payload_size_t must remain 4 bytes");
static_assert(sizeof(enc_chunk_size_t) == 4, "enc_chunk_size_t must remain 4 bytes");
static_assert(sizeof(file_size_t) == 4, "file_size_t must remain 4 bytes");
static_assert(sizeof(packet_num_t) == 2, "packet_num_t must remain 2 bytes");
static_assert(sizeof(total_packets_t) == 2, "total_packets_t must remain 2 bytes");
static_assert(sizeof(checksum_t) == 4, "checksum_t must remain 4 bytes");

static_assert(std::is_unsigned_v<version_t>, "version_t must be unsigned");
static_assert(std::is_unsigned_v<code_t>, "code_t must be unsigned");
static_assert(std::is_unsigned_v<payload_size_t>, "payload_size_t must be unsigned");

TEST_CASE("Protocol field constants are non-zero and internally consistent", "[protocol][fields]")
{
    REQUIRE(UNIQUE_ID_LEN > 0);
    REQUIRE(RSA_KEY_LEN > 0);
    REQUIRE(USERNAME_LEN > 1);
    REQUIRE(FILE_NAME_LEN > 1);

    REQUIRE(protocol_test::request::kHeaderSize == UNIQUE_ID_LEN + sizeof(version_t) + sizeof(code_t) + sizeof(payload_size_t));
    REQUIRE(protocol_test::request::kFixedPayloadSize
            == USERNAME_LEN
               + RSA_KEY_LEN
               + sizeof(enc_chunk_size_t)
               + sizeof(file_size_t)
               + sizeof(packet_num_t)
               + sizeof(total_packets_t)
               + FILE_NAME_LEN);
}

TEST_CASE("Request username field keeps fixed-width C-string behavior", "[protocol][fields][username]")
{
    SECTION("empty username")
    {
        Request request;
        request.get_payload().set_username("");

        const auto serialized = request.serialize();
        const auto expected = protocol_test::make_fixed_c_string_field<USERNAME_LEN>("");

        REQUIRE(request.get_payload().get_username().empty());
        REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetUsername, USERNAME_LEN)
                == protocol_test::to_vector(expected));
    }

    SECTION("normal username")
    {
        Request request;
        request.get_payload().set_username("Alice_1");

        const auto serialized = request.serialize();
        const auto expected = protocol_test::make_fixed_c_string_field<USERNAME_LEN>("Alice_1");

        REQUIRE(request.get_payload().get_username() == "Alice_1");
        REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetUsername, USERNAME_LEN)
                == protocol_test::to_vector(expected));
    }

    SECTION("username exactly USERNAME_LEN - 1")
    {
        const std::string exact(USERNAME_LEN - 1, 'u');

        Request request;
        request.get_payload().set_username(exact);

        const auto serialized = request.serialize();
        const auto username_field = protocol_test::slice(serialized, protocol_test::request::kOffsetUsername, USERNAME_LEN);
        const auto expected = protocol_test::make_fixed_c_string_field<USERNAME_LEN>(exact);

        REQUIRE(request.get_payload().get_username() == exact);
        REQUIRE(username_field == protocol_test::to_vector(expected));
        REQUIRE(username_field.back() == '\0');
    }

    SECTION("username at or above USERNAME_LEN truncates to USERNAME_LEN - 1")
    {
        const std::string oversized(USERNAME_LEN + 12, 'z');

        Request request;
        request.get_payload().set_username(oversized);

        const auto serialized = request.serialize();
        const auto username_field = protocol_test::slice(serialized, protocol_test::request::kOffsetUsername, USERNAME_LEN);
        const auto expected = protocol_test::make_fixed_c_string_field<USERNAME_LEN>(oversized);

        REQUIRE(request.get_payload().get_username() == oversized.substr(0, USERNAME_LEN - 1));
        REQUIRE(username_field == protocol_test::to_vector(expected));
        REQUIRE(username_field.back() == '\0');
    }
}

TEST_CASE("Filename fields keep fixed-width truncation and null termination behavior", "[protocol][fields][filename]")
{
    SECTION("empty request filename")
    {
        Request request;
        request.get_payload().set_file_name("");

        const auto serialized = request.serialize();
        const auto expected = protocol_test::make_fixed_c_string_field<FILE_NAME_LEN>("");

        REQUIRE(request.get_payload().get_file_name().empty());
        REQUIRE(protocol_test::slice(serialized, protocol_test::request::kOffsetFileName, FILE_NAME_LEN)
                == protocol_test::to_vector(expected));
    }

    SECTION("request filename exactly FILE_NAME_LEN - 1")
    {
        const std::string exact(FILE_NAME_LEN - 1, 'f');

        Request request;
        request.get_payload().set_file_name(exact);

        const auto serialized = request.serialize();
        const auto file_name_field = protocol_test::slice(serialized, protocol_test::request::kOffsetFileName, FILE_NAME_LEN);
        const auto expected = protocol_test::make_fixed_c_string_field<FILE_NAME_LEN>(exact);

        REQUIRE(request.get_payload().get_file_name() == exact);
        REQUIRE(file_name_field == protocol_test::to_vector(expected));
        REQUIRE(file_name_field.back() == '\0');
    }

    SECTION("request filename at or above FILE_NAME_LEN truncates")
    {
        const std::string oversized(FILE_NAME_LEN + 20, 'n');

        Request request;
        request.get_payload().set_file_name(oversized);

        const auto serialized = request.serialize();
        const auto file_name_field = protocol_test::slice(serialized, protocol_test::request::kOffsetFileName, FILE_NAME_LEN);
        const auto expected = protocol_test::make_fixed_c_string_field<FILE_NAME_LEN>(oversized);

        REQUIRE(request.get_payload().get_file_name() == oversized.substr(0, FILE_NAME_LEN - 1));
        REQUIRE(file_name_field == protocol_test::to_vector(expected));
        REQUIRE(file_name_field.back() == '\0');
    }

    SECTION("response payload filename follows same truncation contract")
    {
        const std::string oversized(FILE_NAME_LEN + 9, 'r');

        ResponsePayload payload;
        payload.set_file_name(oversized);

        REQUIRE(payload.get_file_name() == oversized.substr(0, FILE_NAME_LEN - 1));
    }
}
