/**
 * @file request.cpp
 * @brief Implements client request models and request serialization.
 *
 * @details
 * This module implements the request-side protocol structures used by the
 * client. It provides accessors for request header and payload fields, handles
 * fixed-size protocol buffers, and serializes complete requests into the binary
 * format sent to the server.
 *
 * @author Tehila Cahnaman
 */

#include "protocol/request.h"

#include <algorithm>
#include <utility>
#include "utils/encoding_utils.h"

namespace
{
    /**
     * @brief Appends a raw numeric field to a byte buffer.
     *
     * @tparam T Numeric field type.
     * @param buffer Destination byte buffer.
     * @param value Value to append.
     */
    template <typename T>
    void append_binary_field(std::vector<char>& buffer, const T& value)
    {
        const auto* first = reinterpret_cast<const char*>(&value);
        buffer.insert(buffer.end(), first, first + sizeof(value));
    }
}

/**
 * @brief Constructs a request header with default client protocol values.
 */
RequestHeader::RequestHeader()
    : user_id_{},
      version_(CLIENT_VERSION),
      request_code_(0),
      payload_size_(0)
{
}

/**
 * @brief Returns the request user ID as a hexadecimal string.
 *
 * @return Hexadecimal representation of the user ID.
 */
std::string RequestHeader::get_user_id() const
{
    return bytes_to_hex(user_id_.data(), user_id_.size());
}

/**
 * @brief Sets the request user ID from a hexadecimal string.
 *
 * @param hex_string Hexadecimal user ID string.
 *
 * @throws std::invalid_argument If the string length does not match the expected user ID size.
 */
void RequestHeader::set_user_id(const std::string& hex_string)
{
    user_id_ = hex_string_to_byte_array<UNIQUE_ID_LEN>(hex_string);
}

/**
 * @brief Returns the protocol version used by the request.
 *
 * @return Client protocol version.
 */
unsigned int RequestHeader::get_version() const
{
    return version_;
}

/**
 * @brief Sets the protocol version used by the request.
 *
 * @param version Protocol version.
 */
void RequestHeader::set_version(version_t version)
{
    version_ = version;
}

/**
 * @brief Returns the request operation code.
 *
 * @return Request operation code.
 */
code_t RequestHeader::get_request_code() const
{
    return request_code_;
}

/**
 * @brief Sets the request operation code.
 *
 * @param request_code Request operation code.
 */
void RequestHeader::set_request_code(code_t request_code)
{
    request_code_ = request_code;
}

/**
 * @brief Returns the serialized payload size.
 *
 * @return Payload size in bytes.
 */
payload_size_t RequestHeader::get_payload_size() const
{
    return payload_size_;
}

/**
 * @brief Sets the serialized payload size.
 *
 * @param payload_size Payload size in bytes.
 */
void RequestHeader::set_payload_size(payload_size_t payload_size)
{
    payload_size_ = payload_size;
}

/**
 * @brief Constructs an empty request payload.
 */
RequestPayload::RequestPayload()
    : username_{},
      public_key_{},
      encrypted_chunk_size_(0),
      file_size_(0),
      packet_number_(0),
      total_packets_(0),
      file_name_{}
{
}

/**
 * @brief Returns the username stored in the fixed-size username field.
 *
 * @return Username as a string.
 */
std::string RequestPayload::get_username() const
{
    return username_.data();
}

/**
 * @brief Copies a username into the fixed-size username field.
 *
 * @details
 * The username is truncated if it exceeds the protocol field size. One byte is
 * reserved for the null terminator because get_username() reads the field as a
 * C-style string.
 *
 * @param username Username to store in the payload.
 */
void RequestPayload::set_username(const std::string& username)
{
    username_.fill('\0');

    const std::size_t copy_len =
        std::min(username.size(), static_cast<std::size_t>(USERNAME_LEN - 1));

    std::copy_n(username.begin(), copy_len, username_.begin());
}

/**
 * @brief Returns the RSA public key as a Base64-encoded string.
 *
 * @return Base64-encoded public key.
 */
std::string RequestPayload::get_public_key() const
{
    return Base64Wrapper::encode(public_key_.data(), public_key_.size());
}

/**
 * @brief Copies an RSA public key into the fixed-size public key field.
 *
 * @param public_key_buffer Pointer to a buffer containing RSA_KEY_LEN bytes.
 *
 * @throws std::invalid_argument If public_key_buffer is null.
 */
void RequestPayload::set_public_key(const char* public_key_buffer)
{
    if (public_key_buffer == nullptr)
    {
        throw std::invalid_argument("Public key buffer cannot be null");
    }

    std::copy(
        public_key_buffer,
        public_key_buffer + RSA_KEY_LEN,
        public_key_.begin()
    );
}

/**
 * @brief Returns the encrypted chunk size.
 *
 * @return Encrypted chunk size in bytes.
 */
enc_chunk_size_t RequestPayload::get_encrypted_file_size() const
{
    return encrypted_chunk_size_;
}

/**
 * @brief Sets the encrypted chunk size.
 *
 * @param size Encrypted chunk size in bytes.
 */
void RequestPayload::set_encrypted_chunk_size(enc_chunk_size_t size)
{
    encrypted_chunk_size_ = size;
}

/**
 * @brief Returns the original file size.
 *
 * @return Original file size in bytes.
 */
file_size_t RequestPayload::get_file_size() const
{
    return file_size_;
}

/**
 * @brief Sets the original file size.
 *
 * @param size Original file size in bytes.
 */
void RequestPayload::set_file_size(file_size_t size)
{
    file_size_ = size;
}

/**
 * @brief Returns the current packet number.
 *
 * @return Packet number in the upload sequence.
 */
packet_num_t RequestPayload::get_packet_number() const
{
    return packet_number_;
}

/**
 * @brief Sets the current packet number.
 *
 * @param packet_number Packet number in the upload sequence.
 */
void RequestPayload::set_packet_number(packet_num_t packet_number)
{
    packet_number_ = packet_number;
}

/**
 * @brief Returns the total number of packets.
 *
 * @return Total packet count.
 */
total_packets_t RequestPayload::get_total_packets() const
{
    return total_packets_;
}

/**
 * @brief Sets the total number of packets.
 *
 * @param total_packets Total packet count.
 */
void RequestPayload::set_total_packets(total_packets_t total_packets)
{
    total_packets_ = total_packets;
}

/**
 * @brief Returns the file name stored in the fixed-size file name field.
 *
 * @return File name as a string.
 */
std::string RequestPayload::get_file_name() const
{
    return file_name_.data();
}

/**
 * @brief Copies a file name into the fixed-size file name field.
 *
 * @details
 * The file name is truncated if it exceeds the protocol field size. One byte is
 * reserved for the null terminator because get_file_name() reads the field as a
 * C-style string.
 *
 * @param file_name File name to store in the payload.
 */
void RequestPayload::set_file_name(const std::string& file_name)
{
    file_name_.fill('\0');

    const std::size_t copy_len =
        std::min(file_name.size(), static_cast<std::size_t>(FILE_NAME_LEN - 1));

    std::copy_n(file_name.begin(), copy_len, file_name_.begin());
}

/**
 * @brief Returns the encrypted file chunk data.
 *
 * @return Const reference to the encrypted chunk buffer.
 */
const std::vector<char>& RequestPayload::get_encrypted_file_data() const
{
    return encrypted_chunk_data_;
}

/**
 * @brief Stores encrypted file chunk data in the payload.
 *
 * @param data Encrypted chunk bytes.
 */
void RequestPayload::set_encrypted_chunk_data(const std::vector<char>& data)
{
    encrypted_chunk_data_ = data;
}

/**
 * @brief Default constructor for the Request class.
 */
Request::Request() = default;

/**
 * @brief Constructs a Request using the provided header and payload.
 *
 * @details
 * Initializes a request object with a given RequestHeader and RequestPayload.
 * The header contains metadata such as client-specific information, protocol
 * details, and operation codes, while the payload holds the variable-sized data
 * for the request.
 *
 * @param header The RequestHeader object containing metadata for the request.
 * @param payload The RequestPayload object representing the request's data.
 */
Request::Request(const RequestHeader& header, RequestPayload payload)
    : header_(header),
      payload_(std::move(payload))
{
}

/**
 * @brief Returns the request header.
 *
 * @return Const reference to the request header.
 */
RequestHeader& Request::get_header()
{
    return header_;
}

/**
 * @brief Sets the request header.
 *
 * @param header Request header.
 */
void Request::set_header(const RequestHeader& header)
{
    header_ = header;
}

/**
 * @brief Returns the request payload.
 *
 * @return Const reference to the request payload.
 */
RequestPayload& Request::get_payload()
{
    return payload_;
}

/**
 * @brief Sets the request payload.
 *
 * @param payload Request payload.
 */
void Request::set_payload(const RequestPayload& payload)
{
    payload_ = payload;
}

/**
 * @brief Serializes the complete request into a binary protocol buffer.
 *
 * @details
 * The serialization order must match the server-side protocol definition:
 * user ID, version, request code, payload size, fixed payload fields, and
 * optional encrypted chunk data.
 *
 * @return Serialized request bytes.
 */
std::vector<char> Request::serialize() const
{
    std::vector<char> buffer;

    buffer.reserve(
        UNIQUE_ID_LEN +
        sizeof(header_.version_) +
        sizeof(header_.request_code_) +
        sizeof(header_.payload_size_) +
        USERNAME_LEN +
        RSA_KEY_LEN +
        sizeof(payload_.encrypted_chunk_size_) +
        sizeof(payload_.file_size_) +
        sizeof(payload_.packet_number_) +
        sizeof(payload_.total_packets_) +
        FILE_NAME_LEN +
        payload_.encrypted_chunk_data_.size()
    );

    buffer.insert(buffer.end(), header_.user_id_.begin(), header_.user_id_.end());

    append_binary_field(buffer, header_.version_);
    append_binary_field(buffer, header_.request_code_);
    append_binary_field(buffer, header_.payload_size_);

    buffer.insert(buffer.end(), payload_.username_.begin(), payload_.username_.end());
    buffer.insert(buffer.end(), payload_.public_key_.begin(), payload_.public_key_.end());

    append_binary_field(buffer, payload_.encrypted_chunk_size_);
    append_binary_field(buffer, payload_.file_size_);
    append_binary_field(buffer, payload_.packet_number_);
    append_binary_field(buffer, payload_.total_packets_);

    buffer.insert(buffer.end(), payload_.file_name_.begin(), payload_.file_name_.end());
    buffer.insert(
        buffer.end(),
        payload_.encrypted_chunk_data_.begin(),
        payload_.encrypted_chunk_data_.end()
    );

    return buffer;
}