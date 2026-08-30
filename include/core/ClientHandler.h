/**
 * @file ClientHandler.h
 * @brief Declares the main client workflow coordinator.
 *
 * @details
 * The ClientHandler class manages the high-level client lifecycle:
 * connecting to the server, handling registration or re-registration,
 * backing up files, and disconnecting from the server.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "core/CommunicationManager.h"

/**
 * @class ClientHandler
 * @brief Coordinates client-side communication and backup operations.
 *
 * @details
 * ClientHandler owns the networking context, socket, and communication manager
 * used by the client. It provides a single public workflow through run(), while
 * keeping connection setup, registration, and backup handling private.
 */
class ClientHandler
{
public:

    /**
    * @brief Constructs a ClientHandler instance and initializes its components.
    */
    ClientHandler();

    /**
    * @brief Sends a disconnect request and closes the client socket.
    */
    void disconnect();

    /**
    * @brief Executes the full client workflow.
    */
    void run();

private:
    /**
    * @brief Connects the client socket to the configured server.
    *
    * @throws boost::system::system_error If resolving or connecting to the server fails.
    */
    void connect();

    /**
    * @brief Performs registration or re-registration based on local client state.
    */
    void handle_registration() const;

    /**
    * @brief Prompts the user for backup input and sends selected files to the server.
    */
    void backup_files();

    /** Provides the I/O context for managing asynchronous operations in the client */
    boost::asio::io_context io_context_;

    /** Represents the TCP socket used for client-server communication */
    boost::asio::ip::tcp::socket socket_;

    /** Manages communication between the client and server */
    CommunicationManager comm_manager_;
};
