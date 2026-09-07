/**
 * @file client_paths.h
 * @brief Declares client-side file path constants and path helpers.
 *
 * @details
 * This module centralizes the names and resolved filesystem paths of files used
 * by the backup client, including local credential files, temporary key files,
 * and the server configuration file.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <filesystem>

namespace fs = std::filesystem;

inline constexpr const char* SRV_CONFIG_FILE = "server_config.json";
inline constexpr const char* CL_INFO_FILE = "me.info";
inline constexpr const char* CL_TRANSFER_FILE = "transfer.info";
inline constexpr const char* CL_USERNAME_FILE = "name.info";
inline constexpr const char* AES_KEY_FILE = "aes.key";
inline constexpr const char* PRIVATE_KEY_FILE = "private.key";

/**
 * @brief Returns the current working directory.
 */
fs::path get_working_dir();

/**
 * @brief Returns the path to the client information file.
 */
fs::path get_client_info_path();

/**
 * @brief Returns the path to the temporary AES key file.
 */
fs::path get_aes_key_path();

/**
 * @brief Returns the path to the private RSA key file.
 */
fs::path get_private_key_path();

/**
 * @brief Returns the path to the server configuration file.
 */
fs::path get_server_config_path();
