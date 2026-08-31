/**
 * @file protocol_formatting.cpp
 * @brief Implements formatting helpers for protocol request and response objects.
 *
 * @details
 * This module implements stream insertion operators used to display protocol
 * structures in a human-readable form during debugging and logging. Binary
 * cryptographic fields are represented by their sizes rather than being written
 * directly to the output stream.
 *
 * It also provides a helper for printing selected binary data in hexadecimal
 * form.
 *
 * @author Tehila Cahnaman
 */

#include "protocol/protocol_formatting.h"

#include <cstddef>
#include <iomanip>
#include <iostream>

#include "protocol/request.h"
#include "protocol/response.h"

/**
 * @brief Writes a request header in human-readable form.
 *
 * @param os Output stream.
 * @param header Request header to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, const RequestHeader& header)
{
    os << "RequestHeader: { "
       << "user_id: " << header.get_user_id() << ", "
       << "version: " << header.get_version() << ", "
       << "request_code: " << header.get_request_code() << ", "
       << "payload_size: " << header.get_payload_size()
       << " }";

    return os;
}

/**
 * @brief Writes a response header in human-readable form.
 *
 * @param os Output stream.
 * @param header Response header to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, const ResponseHeader& header)
{
    os << "ResponseHeader: { "
       << "version: " << header.get_version() << ", "
       << "response_code: " << header.get_response_code() << ", "
       << "payload_size: " << header.get_payload_size()
       << " }";

    return os;
}

/**
 * @brief Writes a request payload in human-readable form.
 *
 * @details
 * Variable-length encrypted file data is represented by its byte count rather
 * than written directly to the output stream.
 *
 * @param os Output stream.
 * @param payload Request payload to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, const RequestPayload& payload)
{
    os << "RequestPayload: { "
       << "username: " << payload.get_username() << ", "
       << "public_key: " << payload.get_public_key() << ", "
       << "encrypted_file_size: " << payload.get_encrypted_file_size() << ", "
       << "orig_file_size: " << payload.get_file_size() << ", "
       << "packet_number: " << payload.get_packet_number() << ", "
       << "total_packets: " << payload.get_total_packets() << ", "
       << "file_name: " << payload.get_file_name() << ", "
       << "encrypted_file_data: <"
       << payload.get_encrypted_file_data().size()
       << " bytes>"
       << " }";

    return os;
}

/**
 * @brief Writes a response payload in human-readable form.
 *
 * @details
 * The encrypted AES key contains binary data and is therefore represented by
 * its byte count instead of being written directly to the output stream.
 *
 * @param os Output stream.
 * @param payload Response payload to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, const ResponsePayload& payload)
{
    os << "ResponsePayload: { "
       << "user_id: " << payload.get_user_id() << ", "
       << "encrypted_aes_key: <"
       << payload.get_encrypted_aes_key().size()
       << " bytes>, "
       << "encrypted_file_size: " << payload.get_encrypted_file_size() << ", "
       << "file_name: " << payload.get_file_name() << ", "
       << "checksum: " << payload.get_checksum()
       << " }";

    return os;
}

/**
 * @brief Writes a complete request in human-readable form.
 *
 * @param os Output stream.
 * @param request Request to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, Request& request)
{
    os << "Request: { "
       << request.get_header() << ", "
       << request.get_payload()
       << " }";

    return os;
}

/**
 * @brief Writes a complete response in human-readable form.
 *
 * @param os Output stream.
 * @param response Response to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, const Response& response)
{
    os << "Response: { "
       << response.get_header() << ", "
       << response.get_payload()
       << " }";

    return os;
}

/**
 * @brief Prints a range of binary data as hexadecimal bytes.
 *
 * @details
 * Bytes are separated by spaces and grouped into rows of sixteen. The existing
 * formatting state of std::cout is restored before the function returns.
 *
 * @param buffer Binary buffer to print.
 * @param start Index of the first byte to print.
 * @param end One-past-the-last byte to print.
 */
void hexify(const char* buffer, std::size_t start, std::size_t end)
{
    if (buffer == nullptr)
    {
        std::cerr << "Cannot hexify a null buffer." << std::endl;
        return;
    }

    if (start >= end)
    {
        std::cerr << "Invalid range!" << std::endl;
        return;
    }

    // Preserve the caller's stream formatting configuration.
    const std::ios::fmtflags original_flags = std::cout.flags();
    const char original_fill = std::cout.fill();

    std::cout << std::hex;

    for (std::size_t i = start; i < end; ++i)
    {
        const auto byte = static_cast<unsigned char>(buffer[i]);

        std::cout << std::setfill('0')
                  << std::setw(2)
                  << static_cast<unsigned int>(byte);

        std::cout << (((i - start + 1) % 16 == 0) ? "\n" : " ");
    }

    std::cout << std::endl;

    std::cout.flags(original_flags);
    std::cout.fill(original_fill);
}
