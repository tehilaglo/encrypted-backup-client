#include <catch2/catch_test_macros.hpp>

#include "protocol/protocol_codes.h"

TEST_CASE("Request protocol codes remain stable", "[protocol][codes][request]")
{
    REQUIRE(protocol::request::REGISTRATION == 100);
    REQUIRE(protocol::request::PUBLIC_KEY_SEND == 101);
    REQUIRE(protocol::request::RE_REGISTRATION == 102);
    REQUIRE(protocol::request::CREATE_BACKUP == 103);
    REQUIRE(protocol::request::CRC_SUCCESS == 120);
    REQUIRE(protocol::request::CRC_ERROR == 121);
    REQUIRE(protocol::request::CRC_FAILURE == 122);
    REQUIRE(protocol::request::DISCONNECT == 130);
}

TEST_CASE("Response protocol codes remain stable", "[protocol][codes][response]")
{
    REQUIRE(protocol::response::REGISTRATION_SUCCESS == 200);
    REQUIRE(protocol::response::REGISTRATION_FAILED == 201);
    REQUIRE(protocol::response::USERNAME_TAKEN == 202);
    REQUIRE(protocol::response::RE_REGISTRATION_SUCCESS == 205);
    REQUIRE(protocol::response::RE_REGISTRATION_FAILED == 206);
    REQUIRE(protocol::response::KEY_SEND_SUCCESS == 210);
    REQUIRE(protocol::response::UPLOAD_RECEIVED == 220);
    REQUIRE(protocol::response::UPLOAD_REJECTED_TOO_LARGE == 221);
    REQUIRE(protocol::response::ACK == 230);
    REQUIRE(protocol::response::FAILED == 231);
}
