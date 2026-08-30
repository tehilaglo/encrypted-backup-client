/**
 * @file client_credentials.h
 * @brief Declares helpers for loading and saving client credential data.
 *
 * @details
 * This module exposes functions for reading locally stored client credentials,
 * including username, user ID, private RSA key, and AES key. It also declares
 * a helper for saving the private RSA key to disk.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <string>

/**
 * @brief Loads the Base64-encoded private RSA key from the client info file.
 *
 * @param file_name Path to the client info file.
 *
 * @return Base64-encoded private key.
 *
 * @throws TracedException if the file format is invalid or the private key is missing.
 */
std::string load_private_key(const std::string& file_name);

/**
 * @brief Loads the username from the first line of the client info file.
 *
 * @param file_name Path to the client info file.
 *
 * @return Trimmed username.
 *
 * @throws TracedException if the file cannot be opened or the username is missing.
 */
std::string load_username(const std::string& file_name);

/**
 * @brief Loads the user ID from the second line of the client info file.
 *
 * @param file_name Path to the client info file.
 *
 * @return Trimmed user ID.
 *
 * @throws TracedException if the file format is invalid or the user ID is missing.
 */
std::string load_user_id(const std::string& file_name);

/**
 * @brief Loads and decodes the AES key from a Base64-encoded key file.
 *
 * @param file_name Path to the AES key file.
 *
 * @return Decoded AES key.
 *
 * @throws TracedException if the file cannot be opened, read, or decoded to data.
 */
std::string load_aes_key(const std::string& file_name);

/**
 * @brief Saves the Base64-encoded private RSA key to the private key file.
 *
 * @param private_key Base64-encoded private RSA key.
 *
 * @throws TracedException if the private key file cannot be opened.
 */
void save_private_key(const std::string& private_key);
