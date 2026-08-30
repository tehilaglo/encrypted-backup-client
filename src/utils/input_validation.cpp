/**
 * @file input_validation.cpp
 * @brief Implements client input validation and CRC32 checksum calculation.
 *
 * @details
 * This module validates usernames, file names, and directory names against the
 * length and character restrictions required by the backup protocol. It also
 * calculates CRC32 checksums using Boost.CRC.
 *
 * @author Tehila Cahnaman
 */

#include "utils/input_validation.h"

#include <cstddef>
#include <regex>
#include <stdexcept>
#include <string>

#include <boost/crc.hpp>

namespace
{
    /** Maximum supported directory-name length, excluding the upper bound. */
    constexpr std::size_t DIRECTORY_NAME_LEN = 1024;

    /**
     * @brief Validates a string against length limits and a regular expression.
     *
     * @param value String to validate.
     * @param minimum_length Minimum accepted length.
     * @param maximum_length Exclusive maximum accepted length.
     * @param pattern Regular expression defining the allowed characters.
     *
     * @return true when the value satisfies all restrictions; otherwise false.
     */
    bool matches_validation_rules(
        const std::string& value,
        std::size_t minimum_length,
        std::size_t maximum_length,
        const std::regex& pattern
    )
    {
        if (value.size() < minimum_length || value.size() >= maximum_length)
        {
            return false;
        }

        return std::regex_match(value, pattern);
    }
}

/**
 * @brief Validates a username against protocol restrictions.
 *
 * @param username Username to validate.
 *
 * @return true if the username has an accepted length and contains only
 * alphanumeric characters, periods, underscores, or hyphens.
 */
bool is_valid_username(const std::string& username)
{
    static const std::regex USERNAME_PATTERN("^[a-zA-Z0-9._-]+$");

    return matches_validation_rules(
        username,
        MIN_USERNAME_LEN,
        USERNAME_LEN,
        USERNAME_PATTERN
    );
}

/**
 * @brief Validates a directory name or path.
 *
 * @param directory_name Directory name or path to validate.
 *
 * @return true if the value is non-empty, shorter than DIRECTORY_NAME_LEN, and
 * contains only supported path characters.
 */
bool is_valid_dir_name(const std::string& directory_name)
{
    static const std::regex DIRECTORY_PATTERN("^[a-zA-Z0-9_\\./-]+$");

    return matches_validation_rules(
        directory_name,
        1,
        DIRECTORY_NAME_LEN,
        DIRECTORY_PATTERN
    );
}

/**
 * @brief Validates a file name against protocol restrictions.
 *
 * @param filename File name to validate.
 *
 * @return true if the name is non-empty, shorter than FILE_NAME_LEN, and
 * contains only alphanumeric characters, periods, underscores, or
 * hyphens.
 */
bool is_valid_filename(const std::string& filename)
{
    static const std::regex FILE_NAME_PATTERN("^[a-zA-Z0-9._-]+$");

    return matches_validation_rules(
        filename,
        1,
        FILE_NAME_LEN,
        FILE_NAME_PATTERN
    );
}

/**
 * @brief Calculates the CRC32 checksum of a data buffer.
 *
 * @param buffer Pointer to the data buffer.
 * @param buffer_size Number of bytes to process.
 *
 * @return Calculated CRC32 checksum.
 *
 * @throws std::invalid_argument If buffer is null while buffer_size is greater
 * than zero.
 */
checksum_t calculate_crc32(
    const char* buffer,
    std::size_t buffer_size
)
{
    if (buffer == nullptr && buffer_size > 0)
    {
        throw std::invalid_argument("CRC input buffer cannot be null.");
    }

    boost::crc_32_type crc;
    crc.process_bytes(buffer, buffer_size);

    return crc.checksum();
}
