/**
 * @file request.h
 * @brief Defines client request structures for the backup communication protocol.
 *
 * @details
 * This module defines the request-side protocol model used by the client.
 * A request is composed of a fixed-size header and a fixed-size/variable-size
 * payload section. The Request class is responsible for serializing these
 * fields into the binary format expected by the server.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <array>
#include <string>
#include <vector>

#include "protocol/protocol_types.h"

class ClientHandler;
class CommunicationManager;
class FileAuthentication;

/**
 * @class RequestHeader
 * @brief Represents the fixed-size metadata section of a client request.
 *
 * @details
 * RequestHeader stores protocol-level metadata such as the client user ID,
 * protocol version, request operation code, and payload size. These fields are
 * serialized before the request payload.
 */
class RequestHeader
{
    friend class Request;

public:
    /**
    * @brief Constructs a request header with default client protocol values.
    */
    RequestHeader();

    /**
     * @brief Returns the request user ID as a hexadecimal string.
     *
     * @return Hexadecimal representation of the user ID.
     */
    std::string get_user_id() const;

    /**
     * @brief Sets the request user ID from a hexadecimal string.
     *
     * @param hex_string Hexadecimal user ID string.
     *
     * @throws std::invalid_argument If the string length does not match the expected user ID size.
     */
    void set_user_id(const std::string& hex_string);

    /**
     * @brief Retrieves the protocol version associated with the request header.
     *
     * @return The protocol version as an unsigned integer.
     */
    unsigned int get_version() const;

    /**
     * @brief Sets the protocol version associated with the request header.
     *
     * @param version The protocol version to be set for this request.
     */
    void set_version(version_t version);

    /**
     * @brief Retrieves the request operation code from the request header.
     *
     * @return The operation code of the request as an unsigned 16-bit integer.
     */
    code_t get_request_code() const;

    /**
     * @brief Sets the request operation code for the request header.
     *
     * @param request_code The operation code to set in the request header.
     */
    void set_request_code(code_t request_code);

    /**
     * @brief Retrieves the size of the serialized request payload in bytes.
     *
     * @return The size of the request payload in bytes.
     */
    payload_size_t get_payload_size() const;

    /**
     * @brief Sets the payload size for the request.
     *
     * @param payload_size The size of the request payload in bytes.
     */
    void set_payload_size(payload_size_t payload_size);

private:
    /** Defines the protocol version used by the client */
    static constexpr version_t CLIENT_VERSION = 3;

    /** Stores the unique identifier for a client request */
    std::array<char, UNIQUE_ID_LEN> user_id_;

    /** Represents the protocol version associated with the request header */
    version_t version_;

    /** Represents the operation code associated with a client request */
    code_t request_code_;

    /** Represents the size of the serialized request payload in bytes */
    payload_size_t payload_size_;
};

/**
 * @class RequestPayload
 * @brief Represents the variable-sized data section of a client request.
 *
 * @details
 * RequestPayload encapsulates the main body of a request, which typically contains
 * application-specific data. This section is serialized after the metadata defined
 * in the request header and can vary in size depending on the operation being
 * performed.
 */
class RequestPayload
{
    friend class Request;

public:
    /**
    * @brief Constructs an empty request payload.
    */
    RequestPayload();

    /**
    * @brief Returns the username stored in the fixed-size username field.
    *
    * @return Username as a string.
    */
    std::string get_username() const;

    /**
    * @brief Copies a username into the fixed-size username field.
    *
    * @param username Username to store in the payload.
    */
    void set_username(const std::string& username);

    /**
     * @brief Returns the RSA public key as a Base64-encoded string.
     *
     * @return Base64-encoded public key.
     */
    std::string get_public_key() const;

    /**
     * @brief Copies an RSA public key into the fixed-size public key field.
     *
     * @param public_key_buffer Pointer to a buffer containing RSA_KEY_LEN bytes.
     *
     * @throws std::invalid_argument If public_key_buffer is null.
     */
    void set_public_key(const char* public_key_buffer);

    /**
     * @brief Retrieves the size of an encrypted chunk of a file.
     *
     * @return The size of an encrypted chunk, represented as an unsigned 32-bit integer.
     */
    enc_chunk_size_t get_encrypted_file_size() const;

    /**
     * @brief Sets the size of an encrypted chunk for the request payload.
     *
     * @param size The size of the encrypted chunk, represented as an unsigned 32-bit integer.
     */
    void set_encrypted_chunk_size(enc_chunk_size_t size);

    /**
     * @brief Returns the original file size.
     *
     * @return Original file size in bytes.
     */
    file_size_t get_file_size() const;

    /**
     * @brief Sets the size of the file associated with the request payload.
     *
     * @param size The total size of the file in bytes.
     */
    void set_file_size(file_size_t size);

    /**
     * @brief Returns the current packet number.
     *
     * @return Packet number in the upload sequence.
     */
    packet_num_t get_packet_number() const;

    /**
     * @brief Sets the current packet number.
     *
     * @param packet_number Packet number in the upload sequence.
     */
    void set_packet_number(packet_num_t packet_number);

    /**
     * @brief Returns the total number of packets.
     *
     * @return Total packet count.
     */
    total_packets_t get_total_packets() const;

    /**
     * @brief Sets the total number of packets required to transmit the complete file.
     *
     * @param total_packets The total number of packets, represented as an unsigned 16-bit integer.
     */
    void set_total_packets(total_packets_t total_packets);

    /**
     * @brief Returns the file name stored in the fixed-size file name field.
     *
     * @return File name as a string.
     */
    std::string get_file_name() const;

    /**
     * @brief Copies a file name into the fixed-size file name field.
     *
     * @param file_name File name to store in the payload.
     */
    void set_file_name(const std::string& file_name);

    /**
     * @brief Retrieves the encrypted chunk data of a file.
     *
     * @return A constant reference to a vector of characters containing
     * the encrypted file data.
     */
    const std::vector<char>& get_encrypted_file_data() const;

    /**
     * @brief Stores encrypted file chunk data in the payload.
     *
     * @param data Encrypted chunk bytes.
     */
    void set_encrypted_chunk_data(const std::vector<char>& data);


private:
    /** Stores the username of the client in a fixed-size character array */
    std::array<char, USERNAME_LEN> username_;

    /** Holds the public key used for cryptographic operations */
    std::array<char, RSA_KEY_LEN> public_key_;

    /** Represents the size of an encrypted chunk of data in bytes */
    enc_chunk_size_t encrypted_chunk_size_;

    /** Represents the total unencrypted size of a file in bytes */
    file_size_t file_size_;

    /** Tracks the sequence number of a specific data packet */
    packet_num_t packet_number_;

    /** Represents the total number of packets required to transmit a complete file */
    total_packets_t total_packets_;

    /** Represents the name of the file associated with the request */
    std::array<char, FILE_NAME_LEN> file_name_;

    /** Stores the encrypted chunk data of a file during transmission or processing */
    std::vector<char> encrypted_chunk_data_;
};

/**
 * @class Request
 * @brief Represents a client request containing metadata and a payload.
 *
 * @details
 * The Request class encapsulates the data and metadata sent by a client,
 * including operation details and any additional information necessary
 * to process the request. It provides functionality to manage and manipulate
 * the request's contents in a way that aligns with protocol specifications.
 */
class Request
{
public:
    /**
    * @brief Default constructor for the Request class.
    */
    Request();

    /**
     * @brief Constructs a request from an existing header and payload.
     *
     * @param header Request header.
     * @param payload Request payload.
     */
    Request(const RequestHeader& header, RequestPayload payload);

    /**
     * @brief Retrieves the header of the current request or data packet.
     *
     * @return Const reference to the request header.
     */
    RequestHeader& get_header();

    /**
     * @brief Sets the metadata section of the request.
     *
     * @param header The RequestHeader object containing metadata to be set.
     */
    void set_header(const RequestHeader& header);

    /**
     * @brief Retrieves the payload associated with the request.
     *
     * @return The payload data of the request as a string or binary buffer,
     * depending on the implementation.
     */
    RequestPayload& get_payload();

    /**
     * @brief Sets the payload for the request.
     *
     * @param payload The RequestPayload object to set as the request's payload.
     */
    void set_payload(const RequestPayload& payload);

    /**
     * @brief Serializes the object into a format suitable for storage or transmission.
     *
     * @return A byte stream representing the serialized form of the object.
     */
    std::vector<char> serialize() const;

private:
    /** Represents the metadata section of a Request object */
    RequestHeader header_;
    /** Represents the variable-size data section of a client request */
    RequestPayload payload_;
};
