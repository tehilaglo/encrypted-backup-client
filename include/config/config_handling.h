/**
 * @file config_handling.h
 * @brief Declares configuration-loading helpers for the backup client.
 *
 * @details
 * This module exposes utilities for reading client configuration files.
 * Currently, it provides a helper for loading the server host and port from
 * a JSON configuration file.
 *
 * Expected JSON structure:
 * @code
 * {
 *   "server": {
 *     "host": "127.0.0.1",
 *     "port": 1234
 *   }
 * }
 * @endcode
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <string>
#include <utility>

/**
 * @brief Loads the server address from a JSON configuration file.
 *
 * @param file_name Path to the JSON configuration file.
 *
 * @return Pair containing the server host/IP and port.
 *
 * @throws TracedException if the configuration file cannot be opened.
 * @throws boost::json::system_error if the JSON is malformed.
 * @throws std::out_of_range if the configured port is outside the valid range.
 * @throws std::exception for missing or incorrectly typed JSON fields.
 */
std::pair<std::string, uint16_t> load_server_address(const std::string& file_name);
