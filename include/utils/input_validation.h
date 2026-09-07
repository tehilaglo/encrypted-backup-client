/**
* @file input_validation.h
 * @brief Declares client input-validation and CRC32 checksum utilities.
 *
 * @details
 * This module provides validation helpers for usernames, file names, and
 * directory names used by the encrypted backup client. It also defines the
 * client-facing exception type and exposes CRC32 checksum calculation for file
 * integrity verification.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>

#include "protocol/protocol_types.h"

/**
 * @class ClientException
 * @brief Represents user-facing client errors.
 *
 * @details
 * ClientException is used for recoverable client-side failures that can be
 * presented directly to the user, such as invalid input or unsupported files.
 */
class ClientException : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

/**
 * @class UserCancelledException
 * @brief Signals that the user intentionally cancelled the current workflow.
 */
class UserCancelledException final : public ClientException
{
public:
    explicit UserCancelledException(
        const std::string& message = "Operation cancelled by user."
    )
        : ClientException(message)
    {
    }
};

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
);

/**
 * @brief Validates a username against protocol restrictions.
 *
 * @param username Username to validate.
 *
 * @return true if the username has an accepted length and contains only
 * alphanumeric characters, periods, underscores, or hyphens.
 */
bool is_valid_username(const std::string& username);

/**
 * @brief Validates a file name against protocol restrictions.
 *
 * @param filename File name to validate.
 *
 * @return true if the name is non-empty, shorter than FILE_NAME_LEN, and
 * contains only alphanumeric characters, periods, underscores, or
 * hyphens.
 */
bool is_valid_filename(const std::string& filename);

/**
 * @brief Validates a directory name or path.
 *
 * @param directory_name Directory name or path to validate.
 *
 * @return true if the value is non-empty, shorter than DIRECTORY_NAME_LEN, and
 * contains only supported path characters.
 */
bool is_valid_dir_name(const std::string& directory_name);
