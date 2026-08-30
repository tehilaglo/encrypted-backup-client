/**
 * @file encoding_utils.h
 * @brief Declares encoding, decoding, and byte-formatting utilities.
 *
 * @details
 * This module provides helpers for converting binary data to hexadecimal text,
 * converting hexadecimal strings back to fixed-size byte arrays, and performing
 * Base64 encoding and decoding through Crypto++.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>

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
std::string bytes_to_hex(const char* data, std::size_t size);

/**
 * @class Base64Wrapper
 * @brief Provides Base64 encoding and decoding operations.
 *
 * @details
 * The class wraps Crypto++ Base64 filters and exposes static methods for
 * encoding strings or raw byte buffers and decoding Base64-encoded strings.
 */
class Base64Wrapper
{
public:
    static std::string encode(const std::string& str);

    static std::string decode(const std::string& str);

    static std::string encode(const char* data, std::size_t size);
};

/**
 * @brief Converts a hexadecimal string to a fixed-size byte array.
 *
 * @tparam N Number of bytes expected in the resulting array.
 *
 * @param hex_string Hexadecimal input containing exactly two characters per byte.
 *
 * @return Byte array containing the decoded values.
 *
 * @throws std::invalid_argument If the input length does not equal `N * 2`, or
 *         if the input contains invalid hexadecimal characters.
 */
template <std::size_t N>
std::array<char, N> hex_string_to_byte_array(
    const std::string& hex_string
)
{
    if (hex_string.size() != N * 2)
    {
        throw std::invalid_argument(
            "Hex string length must be exactly "
            + std::to_string(N * 2)
            + " characters."
        );
    }

    std::array<char, N> byte_array{};

    for (std::size_t index = 0; index < N; ++index)
    {
        const std::size_t hex_offset = index * 2;

        try
        {
            std::size_t parsed_characters = 0;

            const unsigned long value = std::stoul(
                hex_string.substr(hex_offset, 2),
                &parsed_characters,
                16
            );

            // Each iteration must consume exactly one two-character hex byte.
            if (parsed_characters != 2)
            {
                throw std::invalid_argument("Invalid hexadecimal byte.");
            }

            byte_array[index] = static_cast<char>(value);
        }
        catch (const std::exception&)
        {
            throw std::invalid_argument(
                "Invalid hexadecimal value at position "
                + std::to_string(hex_offset)
                + "."
            );
        }
    }

    return byte_array;
}
