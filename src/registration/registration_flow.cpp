/**
 * @file registration_flow.cpp
 * @brief Handles the client registration flow with the backup server.
 *
 * @details
 * This module prompts the user for a valid username, sends a registration
 * request to the server, stores the assigned user ID on successful registration,
 * and completes the RSA/AES key exchange flow.
 *
 * @author Tehila Cahnaman
 */

#include "registration/registration_flow.h"

#include <fstream>
#include <iostream>
#include <string>

#include "config/client_paths.h"
#include "core/CommunicationManager.h"
#include "protocol/request.h"
#include "protocol/response.h"
#include "registration/key_exchange.h"
#include "ui/console_ui.h"
#include "ui/input_keywords.h"
#include "utils/input_validation.h"
#include "utils/logger.h"


namespace {
    /**
     * @brief Calculates the fixed payload size used by registration-related requests.
     *
     * @return Payload size in bytes.
     */
    payload_size_t get_registration_payload_size()
    {
        return USERNAME_LEN + RSA_KEY_LEN
               + sizeof(enc_chunk_size_t)
               + sizeof(file_size_t)
               + sizeof(packet_num_t)
               + sizeof(total_packets_t)
               + FILE_NAME_LEN;
    }

    /**
     * @brief Sends a registration request to the server.
     *
     * @param comm_manager Communication manager used to send the request.
     * @param username Username requested by the client.
     */
    void send_registration_request(const CommunicationManager& comm_manager,
                                   const std::string& username)
    {
        Request req;

        req.get_header().set_request_code(protocol::request::REGISTRATION);
        req.get_header().set_payload_size(get_registration_payload_size());

        req.get_payload().set_username(username);

        comm_manager.send_request(req);
    }

    /**
     * @brief Stores the username and server-assigned user ID in the client info file.
     *
     * @param username Registered username.
     * @param user_id Server-assigned user ID.
     *
     * @throws TracedException if the client info file cannot be opened.
     */
    void save_client_registration_info(const std::string& username,
                                       const std::string& user_id)
    {
        std::ofstream client_info_file(get_client_info_path());

        if (!client_info_file.is_open())
        {
            throw TracedException("Failed to open " + get_client_info_path().string());
        }

        client_info_file << username << '\n';
        client_info_file << user_id << '\n';
    }

    /**
     * @brief Handles the server response to a registration request.
     *
     * @param response Server response.
     * @param username Username used in the registration request.
     *
     * @throws ClientException if registration fails due to invalid user-facing input.
     * @throws TracedException if the server fails or returns an unexpected response code.
     */
    void handle_registration_response(const Response& response,
                                      const std::string& username)
    {
        const code_t response_code = response.get_header().get_response_code();

        if (response_code == protocol::response::REGISTRATION_FAILED)
        {
            throw ClientException(
                "Registration failed. Make sure all details are correct, then give it another go!"
            );
        }

        if (response_code == protocol::response::FAILED)
        {
            throw TracedException("Server error: Registration request failed.");
        }

        if (response_code == protocol::response::REGISTRATION_SUCCESS)
        {
            save_client_registration_info(
                username,
                response.get_payload().get_user_id()
            );
            return;
        }

        throw TracedException(
            "Unexpected response code: Received code '"
            + std::to_string(response_code)
            + "' during registration."
        );
    }

    /**
     * @brief Prompts the user until a valid username is entered.
     *
     * @return Valid username.
     *
     * @throws UserCancelledException if the user enters `quit` or closes the
     * input stream.
     */
    std::string prompt_valid_username()
    {
        std::string username;

        while (true)
        {
            std::cout << Color::GREEN
                  << "Please enter a username."
                  << std::endl
                  << "Type '" << input_keywords::CANCEL << "' to cancel:"
                  << Color::RESET << std::endl;

            if (!(std::cin >> username))
            {
                throw UserCancelledException("Registration cancelled.");
            }

            if (username == input_keywords::CANCEL)
            {
                throw UserCancelledException("Registration cancelled.");
            }

            if (is_valid_username(username))
            {
                return username;
            }

            std::cout << Color::YELLOW
                      << "Oops! Username length must be between "
                      << MIN_USERNAME_LEN
                      << " and "
                      << USERNAME_LEN - 1
                      << " and contain alphanumeric and underscore characters only. "
                      << "Please try again."
                      << Color::RESET << std::endl;
        }
    }
}

/**
 * @brief Runs the full client registration flow.
 *
 * @param comm_manager Communication manager used for server communication.
 *
 * @details
 * The function repeatedly prompts for a username until registration succeeds
 * or a non-recoverable error occurs. After successful registration, it completes
 * the RSA public key exchange and stores the AES key received from the server.
 *
 * @throws ClientException for user-facing registration errors.
 * @throws TracedException for unexpected server, protocol, or file errors.
 */
void client_registration(const CommunicationManager& comm_manager)
{
    std::string username;

    while (true)
    {
        username = prompt_valid_username();

        send_registration_request(comm_manager, username);

        const Response response = comm_manager.receive_response();
        const code_t response_code = response.get_header().get_response_code();

        if (response_code == protocol::response::USERNAME_TAKEN)
        {
            std::cout << Color::YELLOW
                      << "Username is taken. Please try again."
                      << Color::RESET << std::endl;
            continue;
        }

        handle_registration_response(response, username);
        break;
    }

    complete_registration_key_exchange(comm_manager);

    std::cout << Color::GREEN << Color::BOLD
              << "Registration Successful! Welcome " << username
              << "! We’re excited to have you with us."
              << Color::RESET << std::endl;
}
