/**
 * @file config_handling.cpp
 * @brief Implements configuration-loading helpers for the backup client.
 *
 * @details
 * This module reads the client configuration file and extracts the server
 * connection details required to open the TCP connection.
 *
 * @author Tehila Cahnaman
 */

#include "config/config_handling.h"

#include <boost/json/src.hpp>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include "utils/logger.h"

namespace
{
    /** Maximum valid TCP/UDP port number, inclusive. */
    constexpr int MAX_PORT_NUMBER = 65535;
}

/**
 * @brief Loads the server host and port from a JSON configuration file.
 *
 * @param file_name Path to the JSON configuration file.
 *
 * @return Pair containing the server host/IP and port.
 *
 * @throws TracedException if the configuration file cannot be opened.
 * @throws boost::json::system_error if the JSON content is malformed.
 * @throws std::out_of_range if the configured port is outside the valid range.
 * @throws std::exception for missing or incorrectly typed JSON fields.
 */
std::pair<std::string, uint16_t> load_server_address(const std::string& file_name)
{
    std::ifstream config_file(file_name);

    if (!config_file.is_open())
    {
        throw TracedException("Failed to open " + file_name);
    }

    std::stringstream buffer;
    buffer << config_file.rdbuf();

    const boost::json::value config = boost::json::parse(buffer.str());

    const boost::json::value& server = config.at("server");

    const std::string server_ip = server.at("host").as_string().c_str();
    const int port = static_cast<int>(server.at("port").as_int64());

    if (port < 0 || port > MAX_PORT_NUMBER)
    {
        throw std::out_of_range("Port number out of range");
    }

    return {server_ip, static_cast<uint16_t>(port)};
}
