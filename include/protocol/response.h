/**
 * @file response.h
 * @brief Defines server response structures for the backup communication protocol.
 *
 * @details
 * This module defines the response-side protocol model used by the client.
 * A response is composed of a fixed-size header and a payload section containing
 * response-specific data such as user ID, encrypted AES key, file metadata, and
 * checksum information.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <array>
#include <string>
#include <vector>

#include "protocol/protocol_codes.h"


/**
 * @class ResponseHeader
 * @brief Represents the fixed-size metadata section of a server response.
 *
 * @details
 * ResponseHeader stores protocol-level metadata such as protocol version,
 * response operation/status code, and payload size. These fields are parsed
 * before reading the response payload.
 */
class ResponseHeader
{
    friend class Response;

public:
    /**
     * @brief Constructs a response header with default client protocol values.
     */
    ResponseHeader();

    /**
     * @brief Returns the protocol version from the response header.
     *
     * @return Protocol version.
     */
    unsigned int get_version() const;

    /**
     * @brief Sets the protocol version in the response header.
     *
     * @param version Protocol version.
     */
    void set_version(version_t version);

    /**
     * @brief Returns the response status code.
     *
     * @return Response status code.
     */
    code_t get_response_code() const;

    /**
     * @brief Sets the response status code.
     *
     * @param response_code Response status code.
     */
    void set_response_code(code_t response_code);

    /**
     * @brief Returns the response payload size.
     *
     * @return Payload size in bytes.
     */
    payload_size_t get_payload_size() const;
    
    /**
     * @brief Sets the response payload size.
     *
     * @param payload_size Payload size in bytes.
     */
    void set_payload_size(payload_size_t payload_size);

private:
     /** Stores the protocol version used in the response */
    version_t version_;
    /** Stores the response code in the response header */
    code_t response_code_;
    /** Represents the size of the payload in the server response */
    payload_size_t payload_size_;
};

/**
 * @class ResponsePayload
 * @brief Represents the payload section of a server response.
 *
 * @details
 * ResponsePayload stores response-specific data, including the user ID,
 * encrypted AES key, encrypted file size, file name, and CRC checksum.
 */
class ResponsePayload
{
    friend class Response;
public:
    /**
    * @brief Constructs a response payload with default client protocol values.
    */
    ResponsePayload();

    /**
    * @brief Returns the response user ID as a hexadecimal string.
    *
    * @return Hexadecimal representation of the user ID.
    */
    std::string get_user_id() const;

    /**
    * @brief Sets the response user ID from a hexadecimal string.
    *
    * @param hex_string Hexadecimal user ID string.
    *
    * @throws std::invalid_argument If the string length does not match the expected user ID size.
    */
    void set_user_id(const std::string& hex_string);
    /**
     * @brief Returns the encrypted AES key.
     *
     * @return Const reference to the encrypted AES key bytes.
     */
    const std::vector<char>& get_encrypted_aes_key() const;
    /**
     * @brief Stores the encrypted AES key.
     *
     * @param encrypted_aes_key Encrypted AES key bytes.
     */
    void set_encrypted_aes_key(const std::vector<char>& encrypted_aes_key);

    /**
    * @brief Returns the encrypted file size.
    *
    * @return Encrypted file size in bytes.
    */
    enc_chunk_size_t get_encrypted_file_size() const;

    /**
    * @brief Sets the encrypted file size.
    *
    * @param size Encrypted file size in bytes.
    */
    void set_encrypted_file_size(enc_chunk_size_t size);

    /**
    * @brief Returns the response file name.
    *
    * @return File name as a string.
    */
    std::string get_file_name() const;

    /**
    * @brief Copies a file name into the fixed-size response file name field.
    *
    * @param file_name File name to store.
    */
    void set_file_name(const std::string& file_name);

    /**
     * @brief Retrieves the checksum value associated with the response payload.
     *
     * @return The checksum value of the response payload.
     */
    checksum_t get_checksum() const;

    /**
     * @brief Sets the checksum value for the response payload.
     *
     * @param checksum The checksum value to be associated with the response payload.
     */
    void set_checksum(checksum_t checksum);

private:
    /** Stores the unique identifier associated with a user */
    std::array<char, UNIQUE_ID_LEN> user_id_;
    /** Stores the AES key encrypted using a secure encryption algorithm */
    std::vector<char> encrypted_aes_key_;
    /** Represents the size of the encrypted file in bytes */
    enc_chunk_size_t encrypted_file_size_;
    /** Stores the file name associated with the response payload */
    std::array<char, FILE_NAME_LEN> file_name_;
    /** Represents the checksum value associated with the response payload */
    checksum_t checksum_;
};

/**
 * @class Response
 * @brief Represents a complete server response.
 *
 * @details
 * Response combines ResponseHeader and ResponsePayload into a single protocol
 * message. It exposes deserialization logic used by CommunicationManager after
 * receiving raw bytes from the server.
 */
class Response
{
public:
    /**
    * @brief Default constructor for the Response class.
    */
    Response();

    /**
    * @brief Constructs a response from an existing header and payload.
    *
    * @param header Response header.
    * @param payload Response payload.
    */
    Response(const ResponseHeader& header, ResponsePayload payload);

    /**
    * @brief Returns the response header.
    *
    * @return Const reference to the response header.
    */
    const ResponseHeader& get_header() const;

    /**
    * @brief Sets the response header.
    *
    * @param header Response header.
    */
    void set_header(const ResponseHeader& header);

    /**
    * @brief Returns the response payload.
    *
    * @return Const reference to the response payload.
    */
    const ResponsePayload& get_payload() const;

    /**
    * @brief Sets the response payload.
    *
    * @param payload Response payload.
    */
    void set_payload(const ResponsePayload& payload);

    /**
    * @brief Deserializes a binary server response.
    *
    * @param serialized_data Raw response bytes received from the server.
    * @return Parsed Response object.
    *
    * @throws std::runtime_error If the response buffer is malformed or incomplete.
    */
    static Response deserialize(const std::vector<char>& serialized_data);

private:
    /** Represents the metadata section of a server response */
    ResponseHeader header_;
    /** Represents the variable-size data section of a server response */
    ResponsePayload payload_;
};
