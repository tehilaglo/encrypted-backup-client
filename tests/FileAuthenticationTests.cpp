#include <arpa/inet.h>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "config/config_handling.h"
#include "config/client_paths.h"
#include "crypto/AESWrapper.h"
#include "utils/encoding_utils.h"
#include "utils/input_validation.h"
#include "utils/logger.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wkeyword-macro"
#endif
#define private public
#include "crypto/FileAuthentication.h"
#undef private
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

namespace fs = std::filesystem;

template <typename T>
void append_le(std::vector<char>& output, T value)
{
    for (std::size_t i = 0; i < sizeof(T); ++i)
        output.push_back(static_cast<char>((static_cast<std::uint64_t>(value) >> (8 * i)) & 0xff));
}

template <typename T>
void append_be(std::vector<char>& output, T value)
{
    const T network = sizeof(T) == 2
        ? static_cast<T>(htons(static_cast<std::uint16_t>(value)))
        : static_cast<T>(htonl(static_cast<std::uint32_t>(value)));
    const auto* bytes = reinterpret_cast<const char*>(&network);
    output.insert(output.end(), bytes, bytes + sizeof(T));
}

void test_validation_and_hex()
{
    assert(is_valid_username("Alice_1"));
    assert(!is_valid_username("abcd"));
    assert(!is_valid_username("Alice!"));
    assert(is_valid_filename("backup-01.tar"));
    assert(!is_valid_filename("backup/file"));
    assert(!is_valid_filename(""));

    const std::string binary{"\0\x01\x7f\x80\xff", 5};
    assert(bytes_to_hex(binary.data(), binary.size()) == "00017f80ff");
    const auto decoded = hex_string_to_byte_array<5>("00017f80ff");
    assert(std::string(decoded.data(), decoded.size()) == binary);
    try { (void)hex_string_to_byte_array<5>("00017f80fg"); assert(false); }
    catch (const std::invalid_argument&) {}
}

void test_request_serialization()
{
    constexpr std::size_t fixed_size = 16 + 1 + 2 + 4 + 64 + 160 + 4 + 4 + 2 + 2 + 255;
    Request request;
    request.get_header().set_user_id("00112233445566778899aabbccddeeff");
    request.get_header().set_request_code(protocol::request::CREATE_BACKUP);
    request.get_header().set_payload_size(517);
    std::vector<char> key(RSA_KEY_LEN, static_cast<char>(0xa5));
    request.get_payload().set_username("Alice_1");
    request.get_payload().set_public_key(key.data());
    request.get_payload().set_encrypted_chunk_size(3);
    request.get_payload().set_file_size(0x01020304);
    request.get_payload().set_packet_number(2);
    request.get_payload().set_total_packets(7);
    request.get_payload().set_file_name("backup.bin");
    request.get_payload().set_encrypted_chunk_data({'a', '\0', 'z'});

    const auto serialized = request.serialize();
    assert(serialized.size() == fixed_size + 3);
    assert(static_cast<unsigned char>(serialized[16]) == 3);
    assert(static_cast<unsigned char>(serialized[17]) == 103);
    assert(serialized[18] == 0); // request fields are little-endian on the wire
    assert(serialized[19] == 5 && serialized[20] == 2);
    assert(std::string(serialized.end() - 3, serialized.end()) == std::string("a\0z", 3));
}

void test_response_parsing()
{
    const std::string id = "00112233445566778899aabbccddeeff";
    const auto id_bytes = hex_string_to_byte_array<UNIQUE_ID_LEN>(id);
    std::vector<char> payload(id_bytes.begin(), id_bytes.end());
    payload.insert(payload.end(), {'k', 'e', 'y'});
    append_be(payload, enc_chunk_size_t{0x01020304});
    payload.insert(payload.end(), FILE_NAME_LEN, '\0');
    const std::string file_name = "backup.bin";
    std::copy(file_name.begin(), file_name.end(), payload.end() - FILE_NAME_LEN);
    append_be(payload, checksum_t{0xa1b2c3d4});

    std::vector<char> wire{3};
    append_be(wire, code_t{protocol::response::UPLOAD_RECEIVED});
    append_be(wire, static_cast<payload_size_t>(payload.size()));
    wire.insert(wire.end(), payload.begin(), payload.end());
    const Response response = Response::deserialize(wire);
    assert(response.get_header().get_response_code() == protocol::response::UPLOAD_RECEIVED);
    assert(response.get_payload().get_user_id() == id);
    assert(response.get_payload().get_encrypted_aes_key() == std::vector<char>({'k', 'e', 'y'}));
    assert(response.get_payload().get_encrypted_file_size() == 0x01020304);
    assert(response.get_payload().get_file_name() == "backup.bin");
    assert(response.get_payload().get_checksum() == 0xa1b2c3d4);

    wire.resize(10);
    try { (void)Response::deserialize(wire); assert(false); }
    catch (const std::runtime_error&) {}
}

void test_config_parsing()
{
    const fs::path path = fs::temp_directory_path() / "client_config_test.json";
    { std::ofstream file(path); file << R"({"server":{"host":"127.0.0.1","port":54321}})"; }
    const auto address = load_server_address(path.string());
    assert(address == std::make_pair(std::string("127.0.0.1"), std::uint16_t{54321}));
    { std::ofstream file(path); file << R"({"server":{"host":"localhost","port":70000}})"; }
    try { (void)load_server_address(path.string()); assert(false); }
    catch (const std::out_of_range&) {}
    fs::remove(path);
}

void test_file_helpers()
{
    assert(FileAuthentication::get_chunk_size(1024 * 1024 - 1) == 4 * 1024);
    assert(FileAuthentication::get_chunk_size(1024 * 1024) == 64 * 1024);
    const fs::path directory = fs::temp_directory_path() / "file_authentication_tests";
    fs::remove_all(directory); fs::create_directories(directory);
    const fs::path old_path = fs::current_path(); fs::current_path(directory);
    const std::string key(SYMMETRIC_KEY_LEN, 'k');
    { std::ofstream file(AES_KEY_FILE); file << Base64Wrapper::encode(key) << '\n'; }
    const std::vector<char> original{'\0', static_cast<char>(0x80), 'x'};
    { std::ofstream file("binary.dat", std::ios::binary); file.write(original.data(), original.size()); }
    std::size_t size = 0; std::vector<char> data;
    const auto encrypted = FileAuthentication::encrypt_file("binary.dat", "binary.dat", size, data);
    assert(size == original.size() && data == original);
    AESWrapper aes(reinterpret_cast<const unsigned char*>(key.data()), key.size());
    const std::string decrypted = aes.decrypt(encrypted.data(), encrypted.size());
    assert(std::vector<char>(decrypted.begin(), decrypted.end()) == original);
    fs::current_path(old_path); fs::remove_all(directory);
}

int main()
{
    test_validation_and_hex();
    test_request_serialization();
    test_response_parsing();
    test_config_parsing();
    test_file_helpers();
}
