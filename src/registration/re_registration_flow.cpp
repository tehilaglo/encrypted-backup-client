/**
 * @file re_registration_flow.cpp
 * @brief Handles client re-registration with the backup server.
 *
 * @details
 * This module loads the existing client credentials, sends a re-registration
 * request to the server, and completes the RSA/AES key exchange flow for a
 * previously registered client.
 *
 * @author Tehila Cahnaman
 */

#include "registration/re_registration_flow.h"

#include <iostream>
#include <string>

#include "config/client_paths.h"
#include "core/CommunicationManager.h"
#include "protocol/request.h"
#include "protocol/response.h"
#include "registration/client_credentials.h"
#include "registration/key_exchange.h"
#include "ui/console_ui.h"
#include "utils/encoding_utils.h"

namespace {
    /**
     * @brief Calculates the fixed payload size used by registration-related requests.
     * @return Payload size in bytes.
     */
    payload_size_t get_re_registration_payload_size()
    {
        return USERNAME_LEN + RSA_KEY_LEN
               + sizeof(enc_chunk_size_t)
               + sizeof(file_size_t)
               + sizeof(packet_num_t)
               + sizeof(total_packets_t)
               + FILE_NAME_LEN;
    }

    /**
     * @brief Builds a re-registration request from stored client credentials.
     * @param user_id Existing client user ID.
     * @param username Existing client username.
     * @return Fully initialized re-registration request.
     */
    Request build_re_registration_request(const std::string& user_id,
                                          const std::string& username)
    {
        Request req;

        req.get_header().set_user_id(user_id);
        req.get_header().set_request_code(protocol::request::RE_REGISTRATION);
        req.get_header().set_payload_size(get_re_registration_payload_size());

        req.get_payload().set_username(username);

        return req;
    }
}

/**
 * @brief Handles re-registration for an existing client.
 *
 * @param comm_manager Communication manager used to send and receive protocol messages.
 *
 * @details
 * The function loads the locally stored username, user ID, and private RSA key.
 * It then sends a re-registration request to the server and delegates the key
 * response handling to the shared RSA key-exchange handler.
 *
 * @throws TracedException if stored credentials cannot be loaded or the server response is invalid.
 * @throws ClientException if the server rejects re-registration and the client must register again.
 */
void client_re_registration(const CommunicationManager& comm_manager)
{
    const std::string username = load_username(CL_INFO_FILE);
    const std::string user_id = load_user_id(CL_INFO_FILE);
    const std::string private_key_base64 = load_private_key(CL_INFO_FILE);
    const std::string private_key = Base64Wrapper::decode(private_key_base64);

    const Request req = build_re_registration_request(user_id, username);

    comm_manager.send_request(req);

    handle_rsa_key_response(
        comm_manager,
        protocol::response::RE_REGISTRATION_SUCCESS,
        private_key
    );

    std::cout << Color::GREEN << Color::BOLD
              << "Welcome back " << username << "!"
              << Color::RESET << std::endl;
}
