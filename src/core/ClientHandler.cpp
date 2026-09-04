/**
 * @file ClientHandler.cpp
 * @brief Implements the main client workflow.
 *
 * @details
 * This module is responsible for connecting the client to the configured server,
 * performing registration or re-registration, starting the backup flow, and
 * gracefully disconnecting from the server.
 *
 * @author Tehila Cahnaman
 */
#include "core/ClientHandler.h"

#include <boost/asio.hpp>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "config/client_paths.h"
#include "config/config_handling.h"
#include "crypto/FileAuthentication.h"
#include "protocol/protocol_codes.h"
#include "registration/registration_flow.h"
#include "registration/re_registration_flow.h"
#include "ui/backup_selection.h"
#include "ui/console_ui.h"

namespace fs = std::filesystem;

namespace
{
    /** Defines the size of the payload used for the disconnect request */
    constexpr payload_size_t DISCONNECT_PAYLOAD_SIZE =
        USERNAME_LEN + RSA_KEY_LEN + sizeof(enc_chunk_size_t) + FILE_NAME_LEN;
}

/**
 * @brief Constructs a ClientHandler instance and initializes its components.
 */
ClientHandler::ClientHandler()
    : socket_(io_context_),
      comm_manager_(socket_)
{
}

/**
 * @brief Connects the client socket to the configured server.
 *
 * @throws boost::system::system_error If resolving or connecting to the server fails.
 */
void ClientHandler::connect()
{
    const auto [server_ip, server_port] = load_server_address(get_server_config_path());

    boost::asio::ip::tcp::resolver resolver(io_context_);
    boost::system::error_code error;

    const boost::asio::ip::tcp::resolver::query query(
        server_ip,
        std::to_string(server_port)
    );

    const boost::asio::ip::tcp::resolver::iterator endpoint_iterator =
        resolver.resolve(query, error);

    if (error)
    {
        throw boost::system::system_error(
            error,
            "Failed to resolve server address"
        );
    }

    const auto connected_endpoint =
        boost::asio::connect(socket_, endpoint_iterator, error);

    if (error)
    {
        throw boost::system::system_error(
            error,
            "Failed to connect to server " + server_ip +
            " on port " + std::to_string(server_port)
        );
    }

    std::cout << Color::GREEN
              << "Connected to server "
              << connected_endpoint->endpoint().address().to_string()
              << " on port "
              << connected_endpoint->endpoint().port()
              << Color::RESET
              << std::endl;
}

/**
 * @brief Performs registration or re-registration based on local client state.
 *
 * @details
 * If the client information file already exists, the client attempts
 * re-registration. Otherwise, a new registration flow is started.
 */
void ClientHandler::handle_registration() const
{
    if (fs::exists(get_client_info_path()))
    {
        client_re_registration(comm_manager_);
        return;
    }

    client_registration(comm_manager_);
}

/**
 * @brief Prompts the user for backup input and sends selected files to the server.
 */
void ClientHandler::backup_files()
{
    const std::string backup_dir_name = prompt_backup_directory();
    const std::vector<std::string> files = prompt_files_to_backup();

    FileAuthentication auth(comm_manager_);
    auth.backup_files(backup_dir_name, files);
}

/**
 * @brief Sends a disconnect request and closes the client socket.
 *
 * @details
 * The socket is checked before sending to avoid throwing another communication
 * exception when disconnect() is called after a failed connection attempt.
 */
void ClientHandler::disconnect()
{
    if (!socket_.is_open())
    {
        return;
    }

    Request req;
    req.get_header().set_request_code(protocol::request::DISCONNECT);
    req.get_header().set_payload_size(DISCONNECT_PAYLOAD_SIZE);

    comm_manager_.send_request(req);
    socket_.close();
}

/**
 * @brief Executes the full client workflow.
 *
 * @details
 * The workflow order is:
 * 1. Connect to the server.
 * 2. Register or re-register the client.
 * 3. Back up selected files.
 * 4. Disconnect from the server.
 */
void ClientHandler::run()
{
    connect();
    handle_registration();
    backup_files();
    disconnect();
}
