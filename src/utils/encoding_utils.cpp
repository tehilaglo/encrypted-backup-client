/**
 * @file encoding_utils.cpp
 * @brief Implements encoding, decoding, and byte-formatting utilities.
 *
 * @details
 * This module implements hexadecimal conversion and Base64 operations used
 * throughout the encrypted backup client. Base64 encoding and decoding are
 * performed using Crypto++ filters.
 *
 * @author Tehila Cahnaman
 */

#include "utils/encoding_utils.h"

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

/**
 * @brief Converts binary data to a lowercase hexadecimal string.
 *
 * @param data Pointer to the binary data.
 * @param size Number of bytes to convert.
 *
 * @return Hexadecimal representation containing two characters per input byte.
 *
 * @throws std::invalid_argument If data is null while size is greater than zero.
 */
std::string bytes_to_hex(const char* data, std::size_t size)
{
    if (data == nullptr && size > 0)
    {
        throw std::invalid_argument("Input data buffer cannot be null.");
    }

    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');

    for (std::size_t index = 0; index < size; ++index)
    {
        // Convert through unsigned char to avoid sign extension for bytes >= 0x80.
        const auto byte =
            static_cast<unsigned char>(data[index]);

        hex_stream << std::setw(2)
                   << static_cast<unsigned int>(byte);
    }

    return hex_stream.str();
}

/**
 * @brief Encodes a string using Base64.
 *
 * @param str Input string to encode.
 *
 * @return Base64-encoded string.
 */
std::string Base64Wrapper::encode(const std::string& str)
{
    std::string encoded;

    CryptoPP::StringSource source(
        str,
        true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        )
    );

    return encoded;
}

/**
 * @brief Decodes a Base64-encoded string.
 *
 * @param str Base64-encoded input.
 *
 * @return Decoded binary string.
 */
std::string Base64Wrapper::decode(const std::string& str)
{
    std::string decoded;

    CryptoPP::StringSource source(
        str,
        true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)
        )
    );

    return decoded;
}

/**
 * @brief Encodes raw binary data using Base64.
 *
 * @param data Pointer to the binary data.
 * @param size Number of bytes to encode.
 *
 * @return Base64-encoded string without inserted line breaks.
 *
 * @throws std::invalid_argument If data is null while size is greater than zero.
 */
std::string Base64Wrapper::encode(
    const char* data,
    std::size_t size
)
{
    if (data == nullptr && size > 0)
    {
        throw std::invalid_argument("Input data buffer cannot be null.");
    }

    std::string encoded;

    CryptoPP::StringSource source(
        reinterpret_cast<const CryptoPP::byte*>(data),
        size,
        true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded),
            false
        )
    );

    return encoded;
}
