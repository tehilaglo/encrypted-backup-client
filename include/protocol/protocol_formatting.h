/**
 * @file protocol_formatting.h
 * @brief Declares formatting helpers for protocol request and response objects.
 *
 * @details
 * This module provides stream insertion operators for producing human-readable
 * representations of protocol headers, payloads, requests, and responses.
 * It also declares a hexadecimal buffer-dump helper intended for debugging
 * binary protocol data.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <cstddef>
#include <iosfwd>

class RequestHeader;
class ResponseHeader;
class RequestPayload;
class ResponsePayload;
class Request;
class Response;

/**
 * @brief Writes a request header in human-readable form.
 *
 * @param os Output stream.
 * @param header Request header to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, const RequestHeader& header);

/**
 * @brief Writes a response header in human-readable form.
 *
 * @param os Output stream.
 * @param header Response header to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, const ResponseHeader& header);

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
std::ostream& operator<<(std::ostream& os, const RequestPayload& payload);

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
std::ostream& operator<<(std::ostream& os, const ResponsePayload& payload);

/**
 * @brief Writes a complete request in human-readable form.
 *
 * @param os Output stream.
 * @param request Request to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, Request& request);

/**
 * @brief Writes a complete response in human-readable form.
 *
 * @param os Output stream.
 * @param response Response to format.
 * @return Reference to the output stream.
 */
std::ostream& operator<<(std::ostream& os, const Response& response);

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
void hexify(const char* buffer, std::size_t start, std::size_t end);
