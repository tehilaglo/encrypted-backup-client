/**
 * @file client_paths.cpp
 * @brief Implements client-side path helper functions.
 *
 * @details
 * This module resolves file paths used by the backup client relative to the
 * process working directory. Client-owned files are stored in the working
 * directory, while the server configuration file is expected one directory
 * above it.
 *
 * @author Tehila Cahnaman
 */

#include "config/client_paths.h"

/**
 * @brief Returns the current working directory.
 */
fs::path get_working_dir()
{
    return fs::current_path();
}

/**
 * @brief Returns the path to the client information file.
 */
fs::path get_client_info_path()
{
    return get_working_dir() / CL_INFO_FILE;
}

/**
 * @brief Returns the path to the temporary AES key file.
 */
fs::path get_aes_key_path()
{
    return get_working_dir() / AES_KEY_FILE;
}

/**
 * @brief Returns the path to the private RSA key file.
 */
fs::path get_private_key_path()
{
    return get_working_dir() / PRIVATE_KEY_FILE;
}

/**
 * @brief Returns the path to the server configuration file.
 */
fs::path get_server_config_path()
{
    return fs::current_path() / SRV_CONFIG_FILE;
}
