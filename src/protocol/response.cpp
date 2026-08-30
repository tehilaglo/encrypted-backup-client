/**
 * @file response.cpp
 * @brief Implements server response models and response deserialization.
 *
 * @details
 * This module implements the response-side protocol structures used by the
 * client. It provides accessors for response header and payload fields and
 * deserializes binary server responses into structured Response objects.
 *
 * @author Tehila Cahnaman
 */

#include "protocol/response.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include <arpa/inet.h>

#include "utils/encoding_utils.h"

namespace
{
    constexpr std::size_t RESPONSE_HEADER_SIZE =
        sizeof(version_t) + sizeof(code_t) + sizeof(payload_size_t);

    constexpr std::size_t FIXED_RESPONSE_PAYLOAD_SIZE =
        UNIQUE_ID_LEN +
        sizeof(enc_chunk_size_t) +
        FILE_NAME_LEN +
        sizeof(checksum_t);

    /**
     * @brief Verifies that a serialized response contains enough bytes to read a field.
     *
     * @param data Serialized response buffer.
     * @param offset Current read offset.
     * @param bytes_to_read Number of bytes required for the next read.
     *
     * @throws std::runtime_error If the buffer does not contain enough bytes.
     */
    void validate_available_bytes(
        const std::vector<char>& data,
        std::size_t offset,
        std::size_t bytes_to_read
    )
    {
        if (offset > data.size() || bytes_to_read > data.size() - offset)
        {
            throw std::runtime_error("Malformed response: insufficient data");
        }
    }

    /**
     * @brief Reads a raw field from the serialized response buffer.
     *
     * @tparam T Field type to read.
     * @param data Serialized response buffer.
     * @param offset Current read offset, advanced after a successful read.
     * @return Parsed field value.
     *
     * @throws std::runtime_error If the buffer does not contain enough bytes.
     */
    template <typename T>
    T read_binary_field(const std::vector<char>& data, std::size_t& offset)
    {
        validate_available_bytes(data, offset, sizeof(T));

        T value{};
        std::memcpy(&value, data.data() + offset, sizeof(T));
        offset += sizeof(T);

        return value;
    }

    /**
     * @brief Copies a fixed-size byte range from the serialized response buffer.
     *
     * @param data Serialized response buffer.
     * @param offset Current read offset, advanced after a successful copy.
     * @param destination Destination buffer.
     * @param size Number of bytes to copy.
     *
     * @throws std::runtime_error If the buffer does not contain enough bytes.
     */
    void copy_bytes(
        const std::vector<char>& data,
        std::size_t& offset,
        char* destination,
        std::size_t size
    )
    {
        validate_available_bytes(data, offset, size);

        std::memcpy(destination, data.data() + offset, size);
        offset += size;
    }
}

/**
 * @brief Constructs a response header with default client protocol values.
 */
ResponseHeader::ResponseHeader()
    : version_(0),
      response_code_(0),
      payload_size_(0)
{
}

/**
 * @brief Returns the protocol version from the response header.
 *
 * @return Protocol version.
 */
unsigned int ResponseHeader::get_version() const
{
    return version_;
}

/**
 * @brief Sets the protocol version in the response header.
 *
 * @param version Protocol version.
 */
void ResponseHeader::set_version(version_t version)
{
    version_ = version;
}

/**
 * @brief Returns the response status code.
 *
 * @return Response status code.
 */
code_t ResponseHeader::get_response_code() const
{
    return response_code_;
}

/**
 * @brief Sets the response status code.
 *
 * @param response_code Response status code.
 */
void ResponseHeader::set_response_code(code_t response_code)
{
    response_code_ = response_code;
}

/**
 * @brief Returns the response payload size.
 *
 * @return Payload size in bytes.
 */
payload_size_t ResponseHeader::get_payload_size() const
{
    return payload_size_;
}

/**
 * @brief Sets the response payload size.
 *
 * @param payload_size Payload size in bytes.
 */
void ResponseHeader::set_payload_size(payload_size_t payload_size)
{
    payload_size_ = payload_size;
}

/**
 * @brief Constructs a response payload with default client protocol values.
 */
ResponsePayload::ResponsePayload()
    : user_id_{},
      encrypted_file_size_(0),
      file_name_{},
      checksum_(0)
{
}

/**
 * @brief Returns the response user ID as a hexadecimal string.
 *
 * @return Hexadecimal representation of the user ID.
 */
std::string ResponsePayload::get_user_id() const
{
    return bytes_to_hex(user_id_.data(), user_id_.size());
}

/**
 * @brief Sets the response user ID from a hexadecimal string.
 *
 * @param hex_string Hexadecimal user ID string.
 *
 * @throws std::invalid_argument If the string length does not match the expected user ID size.
 */
void ResponsePayload::set_user_id(const std::string& hex_string)
{
    user_id_ = hex_string_to_byte_array<UNIQUE_ID_LEN>(hex_string);
}

/**
 * @brief Retrieves the encrypted AES key stored in the response payload.
 *
 * @details
 * This method returns a constant reference to the encrypted AES key, allowing
 * read-only access to the key stored as a vector of characters. The encrypted
 * AES key is used to decrypt the payload's data during processing or handling
 * of the response.
 *
 * @return A constant reference to the vector containing the encrypted AES key.
 */
const std::vector<char>& ResponsePayload::get_encrypted_aes_key() const
{
    return encrypted_aes_key_;
}

/**
 * @brief Sets the encrypted AES key for the response payload.
 *
 * @details
 * Assigns a new value to the encrypted AES key, which is stored as
 * a vector of characters. The encrypted AES key is used to securely
 * manage the payload's data encryption. This method replaces any
 * previously stored encrypted key with the one provided.
 *
 * @param encrypted_aes_key The new encrypted AES key to be stored.
 */
void ResponsePayload::set_encrypted_aes_key(
    const std::vector<char>& encrypted_aes_key
)
{
    encrypted_aes_key_ = encrypted_aes_key;
}

/**
 * @brief Retrieves the size of the encrypted file in bytes.
 *
 * @details
 * This method returns the size of the encrypted file stored within the response payload.
 * The size is represented in bytes and corresponds to the total size of the encrypted
 * data transmitted or processed as part of the server's response.
 *
 * @return The size of the encrypted file in bytes as an enc_chunk_size_t.
 */
enc_chunk_size_t ResponsePayload::get_encrypted_file_size() const
{
    return encrypted_file_size_;
}

/**
 * @brief Sets the size of the encrypted file in bytes.
 *
 * @details
 * Updates the internal storage for the encrypted file size.
 * This value represents the size of the encrypted file chunks
 * and is used for proper handling of encrypted data during
 * transmission or processing.
 *
 * @param size The size of the encrypted file in bytes.
 */
void ResponsePayload::set_encrypted_file_size(enc_chunk_size_t size)
{
    encrypted_file_size_ = size;
}

/**
 * @brief Returns the response file name.
 *
 * @return File name as a string.
 */
std::string ResponsePayload::get_file_name() const
{
    return file_name_.data();
}

/**
 * @brief Copies a file name into the fixed-size response file name field.
 *
 * @details
 * The file name is truncated if it exceeds the protocol field size. One byte is
 * reserved for the null terminator because get_file_name() reads the field as a
 * C-style string.
 *
 * @param file_name File name to store.
 */
void ResponsePayload::set_file_name(const std::string& file_name)
{
    file_name_.fill('\0');

    const std::size_t copy_len =
        std::min(file_name.size(), static_cast<std::size_t>(FILE_NAME_LEN - 1));

    std::copy_n(file_name.begin(), copy_len, file_name_.begin());
}

/**
 * @brief Retrieves the checksum value associated with the response payload.
 *
 * @return The checksum value of the response payload.
 */
checksum_t ResponsePayload::get_checksum() const
{
    return checksum_;
}

/**
 * @brief Sets the checksum value for the response payload.
 *
 * @param checksum The checksum value to be associated with the response payload.
 */
void ResponsePayload::set_checksum(checksum_t checksum)
{
    checksum_ = checksum;
}

/**
 * @brief Default constructor for the Response class.
 */
Response::Response() = default;

/**
 * @brief Constructs a response from an existing header and payload.
 *
 * @param header Response header.
 * @param payload Response payload.
 */
Response::Response(const ResponseHeader& header, ResponsePayload payload)
    : header_(header),
      payload_(std::move(payload))
{
}

/**
 * @brief Returns the response header.
 *
 * @return Const reference to the response header.
 */
const ResponseHeader& Response::get_header() const
{
    return header_;
}

/**
 * @brief Sets the response header.
 *
 * @param header Response header.
 */
void Response::set_header(const ResponseHeader& header)
{
    header_ = header;
}

/**
 * @brief Returns the response payload.
 *
 * @return Const reference to the response payload.
 */
const ResponsePayload& Response::get_payload() const
{
    return payload_;
}

/**
 * @brief Sets the response payload.
 *
 * @param payload Response payload.
 */
void Response::set_payload(const ResponsePayload& payload)
{
    payload_ = payload;
}

/**
 * @brief Deserializes a binary server response.
 *
 * @details
 * The expected order is:
 * version, response code, payload size, user ID, encrypted AES key,
 * encrypted file size, file name, and checksum.
 *
 * @param serialized_data Raw response bytes received from the server.
 * @return Parsed Response object.
 *
 * @throws std::runtime_error If the response buffer is malformed or incomplete.
 */
Response Response::deserialize(const std::vector<char>& serialized_data)
{
    validate_available_bytes(serialized_data, 0, RESPONSE_HEADER_SIZE);

    Response response;
    std::size_t offset = 0;

    response.header_.version_ = read_binary_field<version_t>(
        serialized_data,
        offset
    );

    const code_t net_response_code = read_binary_field<code_t>(
        serialized_data,
        offset
    );
    response.header_.response_code_ = ntohs(net_response_code);

    const payload_size_t net_payload_size = read_binary_field<payload_size_t>(
        serialized_data,
        offset
    );
    response.header_.payload_size_ = ntohl(net_payload_size);

    if (response.header_.payload_size_ < FIXED_RESPONSE_PAYLOAD_SIZE)
    {
        throw std::runtime_error("Malformed response: invalid payload size");
    }

    const std::size_t expected_size =
        RESPONSE_HEADER_SIZE + response.header_.payload_size_;

    if (serialized_data.size() < expected_size)
    {
        throw std::runtime_error("Malformed response: payload is incomplete");
    }

    copy_bytes(
        serialized_data,
        offset,
        response.payload_.user_id_.data(),
        response.payload_.user_id_.size()
    );

    const std::size_t aes_key_size =
        response.header_.payload_size_ - FIXED_RESPONSE_PAYLOAD_SIZE;

    response.payload_.encrypted_aes_key_.resize(aes_key_size);

    if (aes_key_size > 0)
    {
        copy_bytes(
            serialized_data,
            offset,
            response.payload_.encrypted_aes_key_.data(),
            aes_key_size
        );
    }

    const enc_chunk_size_t net_encrypted_file_size =
        read_binary_field<enc_chunk_size_t>(serialized_data, offset);

    response.payload_.encrypted_file_size_ = ntohl(net_encrypted_file_size);

    copy_bytes(
        serialized_data,
        offset,
        response.payload_.file_name_.data(),
        response.payload_.file_name_.size()
    );

    const checksum_t net_checksum =
        read_binary_field<checksum_t>(serialized_data, offset);

    response.payload_.checksum_ = ntohl(net_checksum);

    return response;
}
