/**
 * @file client_credentials.cpp
 * @brief Loads and stores client credential data used by the backup client.
 *
 * @details
 * This module handles reading the local client information file, including
 * username, user ID, private RSA key, and AES key. It also stores the private
 * RSA key in its dedicated file.
 *
 * The expected client info file format is:
 * 1. Username
 * 2. User ID
 * 3. Base64-encoded private RSA key, possibly spanning multiple lines
 *
 * @author Tehila Cahnaman
 */

#include "registration/client_credentials.h"
#include <boost/algorithm/string.hpp>
#include <filesystem>
#include <fstream>
#include <string>

#include "config/client_paths.h"
#include "utils/encoding_utils.h"
#include "utils/logger.h"

namespace fs = std::filesystem;

namespace
{
    /**
     * @brief Represents the file system path to the private key file.
     *
     * This variable combines the current working directory with the name of the private key file
     * to generate the absolute path for the private key. It is used for operations involving
     * secure storage or retrieval of the private key.
     *
     * @note The path relies on the value defined for `PRIVATE_KEY_FILE` to determine the file name.
     */
    const fs::path PRIVATE_KEY_PATH = fs::current_path() / PRIVATE_KEY_FILE;

/**
 * @brief Opens an input file stream and validates that it was opened successfully.
 *
 * @param file_name Path to the file to open.
 *
 * @return Open input file stream.
 *
 * @throws TracedException if the file cannot be opened.
 */
std::ifstream open_input_file(const std::string& file_name)
{
    std::ifstream file(file_name);

    if (!file.is_open())
    {
        throw TracedException("Failed to open " + file_name);
    }

    return file;
}

/**
 * @brief Reads a required line from a file stream.
 *
 * @param file Input file stream.
 * @param file_name File name used for error reporting.
 * @param error_message Error message prefix.
 *
 * @return The trimmed line content.
 *
 * @throws TracedException if the line cannot be read.
 */
std::string read_required_line(std::ifstream& file,
                               const std::string& file_name,
                               const std::string& error_message)
{
    std::string line;

    if (!std::getline(file, line))
    {
        throw TracedException(error_message + " from " + file_name);
    }

    boost::trim(line);
    return line;
}

}

/**
 * @brief Loads the username from the first line of the client info file.
 *
 * @param file_name Path to the client info file.
 *
 * @return Trimmed username.
 *
 * @throws TracedException if the file cannot be opened or the username is missing.
 */
std::string load_username(const std::string& file_name)
{
    std::ifstream client_info_file = open_input_file(file_name);
    return read_required_line(client_info_file, file_name, "Failed to read username");
}

/**
 * @brief Loads the user ID from the second line of the client info file.
 *
 * @param file_name Path to the client info file.
 *
 * @return Trimmed user ID.
 *
 * @throws TracedException if the file format is invalid or the user ID is missing.
 */
std::string load_user_id(const std::string& file_name)
{
    std::ifstream client_info_file = open_input_file(file_name);

    read_required_line(client_info_file, file_name, "Incorrect file format");
    return read_required_line(client_info_file, file_name, "Failed to read User ID");
}

/**
 * @brief Loads the Base64-encoded private RSA key from the client info file.
 *
 * @param file_name Path to the client info file.
 *
 * @return Base64-encoded private key.
 *
 * @throws TracedException if the file format is invalid or the private key is missing.
 */
std::string load_private_key(const std::string& file_name)
{
    std::ifstream client_info_file = open_input_file(file_name);

    read_required_line(client_info_file, file_name, "Incorrect file format");
    read_required_line(client_info_file, file_name, "Incorrect file format");

    std::string private_key;
    std::string line;

    while (std::getline(client_info_file, line))
    {
        boost::trim(line);

        // Private keys are stored as Base64 text; concatenate all key lines.
        private_key += line;
    }

    if (private_key.empty())
    {
        throw TracedException("Private key not found in " + file_name);
    }

    return private_key;
}

/**
 * @brief Loads and decodes the AES key from a Base64-encoded key file.
 *
 * @param file_name Path to the AES key file.
 *
 * @return Decoded AES key.
 *
 * @throws TracedException if the file cannot be opened, read, or decoded to data.
 */
std::string load_aes_key(const std::string& file_name)
{
    std::ifstream aes_key_file = open_input_file(file_name);
    std::string base64_encoded_key = read_required_line(
        aes_key_file,
        file_name,
        "Failed to read AES key"
    );

    std::string decoded_key = Base64Wrapper::decode(base64_encoded_key);

    if (decoded_key.empty())
    {
        throw TracedException("Decoded AES key is empty.");
    }

    return decoded_key;
}

/**
 * @brief Saves the Base64-encoded private RSA key to the private key file.
 *
 * @param private_key Base64-encoded private RSA key.
 *
 * @throws TracedException if the private key file cannot be opened.
 */
void save_private_key(const std::string& private_key)
{
    std::ofstream priv_key_file(PRIVATE_KEY_PATH);

    if (!priv_key_file.is_open())
    {
        throw TracedException("Failed to open " + std::string(PRIVATE_KEY_FILE));
    }

    priv_key_file << private_key;
}
