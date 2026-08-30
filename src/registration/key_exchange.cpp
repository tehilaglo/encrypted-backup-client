/**
 * @file key_exchange.cpp
 * @brief Handles RSA public key exchange and AES key retrieval during registration.
 *
 * @details
 * This module sends the client's RSA public key to the server, stores the matching
 * private key locally, receives the encrypted AES key from the server, decrypts it,
 * and stores it for later encrypted file-transfer operations.
 *
 * @author Tehila Cahnaman
 */

#include "registration/key_exchange.h"

#include <filesystem>
#include <fstream>
#include <string>

#include "config/client_paths.h"
#include "core/CommunicationManager.h"
#include "protocol/request.h"
#include "protocol/response.h"
#include "registration/client_credentials.h"
#include "utils/encoding_utils.h"
#include "utils/input_validation.h"
#include "utils/logger.h"

namespace {
    /**
     * @brief Calculates the fixed-size request payload used by registration/key-exchange requests.
     *
     * @return Payload size in bytes.
     */
    payload_size_t get_key_exchange_payload_size()
    {
        return USERNAME_LEN + RSA_KEY_LEN
               + sizeof(enc_chunk_size_t)
               + sizeof(file_size_t)
               + sizeof(packet_num_t)
               + sizeof(total_packets_t)
               + FILE_NAME_LEN;
    }

    /**
     * @brief Appends the Base64-encoded private key to the client info file.
     *
     * @param private_key_base64 Base64-encoded RSA private key.
     *
     * @throws TracedException if the client info file cannot be opened.
     */
    void append_private_key_to_client_info(const std::string& private_key_base64)
    {
        std::ofstream client_info_file(get_client_info_path(), std::ios::app);

        if (!client_info_file.is_open())
        {
            throw TracedException("Failed to open " + get_client_info_path().string());
        }

        client_info_file << private_key_base64;
    }

    /**
     * @brief Saves the Base64-encoded AES key to the AES key file.
     *
     * @param aes_key Raw decoded AES key.
     *
     * @throws TracedException if the AES key file cannot be opened.
     */
    void save_aes_key(const std::string& aes_key)
    {
        std::ofstream aes_key_file(get_aes_key_path());

        if (!aes_key_file.is_open())
        {
            throw TracedException("Failed to open " + get_aes_key_path().string());
        }

        aes_key_file << Base64Wrapper::encode(aes_key);
    }

    /**
     * @brief Validates that the response belongs to the currently stored user ID.
     *
     * @param response Response received from the server.
     *
     * @throws TracedException if the response user ID does not match the local user ID.
     */
    void validate_response_user_id(const Response& response)
    {
        const std::string expected_user_id = load_user_id(CL_INFO_FILE);
        const std::string actual_user_id = response.get_payload().get_user_id();

        if (expected_user_id != actual_user_id)
        {
            throw TracedException(
                "User ID mismatch: Expected '" + expected_user_id
                + "', received '" + actual_user_id + "'."
            );
        }
    }
}

/**
 * @brief Sends the client's RSA public key to the server.
 *
 * @param comm_manager Communication manager used to send the request.
 * @param rsa_key_wrapper RSA private wrapper used to generate and expose the matching public key.
 *
 * @details
 * The function loads the stored user ID and username, builds a public-key-send request,
 * stores the generated private key locally in Base64 format, and sends the request to
 * the server.
 *
 * @throws TracedException if local credential files cannot be read or written.
 */
void send_rsa_public_key(const CommunicationManager& comm_manager,
                         RSAPrivateWrapper& rsa_key_wrapper)
{
    Request req;

    const std::string user_id = load_user_id(CL_INFO_FILE);
    const std::string username = load_username(CL_INFO_FILE);

    req.get_header().set_user_id(user_id);
    req.get_header().set_request_code(protocol::request::PUBLIC_KEY_SEND);
    req.get_header().set_payload_size(get_key_exchange_payload_size());

    req.get_payload().set_username(username);

    char public_key_buff[RSA_KEY_LEN] = {};
    rsa_key_wrapper.getPublicKey(public_key_buff, RSA_KEY_LEN);
    req.get_payload().set_public_key(public_key_buff);

    const std::string private_key_base64 =
        Base64Wrapper::encode(rsa_key_wrapper.getPrivateKey());

    append_private_key_to_client_info(private_key_base64);
    save_private_key(private_key_base64);

    comm_manager.send_request(req);
}

/**
 * @brief Handles the server response after RSA key exchange.
 *
 * @param comm_manager Communication manager used to receive the response.
 * @param op_code Expected success response code.
 * @param private_key Raw RSA private key used to decrypt the AES key.
 *
 * @details
 * The function verifies the server response, validates that the response user ID
 * matches the local user ID, decrypts the AES key, and stores it locally in Base64
 * format. If re-registration fails, the local client info file is removed.
 *
 * @throws ClientException if re-registration fails and the user must register again.
 * @throws TracedException if the server response is invalid or unexpected.
 */
void handle_rsa_key_response(const CommunicationManager& comm_manager,
                             uint16_t op_code,
                             const std::string& private_key)
{
    const Response response = comm_manager.receive_response();
    const code_t response_code = response.get_header().get_response_code();

    if (response_code == protocol::response::FAILED)
    {
        throw TracedException("Server error: RSA key response could not be processed.");
    }

    validate_response_user_id(response);

    if (response_code == op_code)
    {
        RSAPrivateWrapper rsa_private_key(private_key);

        // The server sends the AES key encrypted with the client's RSA public key.
        const std::string aes_key = rsa_private_key.decrypt_base64(
            response.get_payload().get_encrypted_aes_key().data()
        );

        save_aes_key(aes_key);
        return;
    }

    if (response_code == protocol::response::RE_REGISTRATION_FAILED)
    {
        std::filesystem::remove(get_client_info_path());

        throw ClientException(
            "It looks like we need to register you again. "
            "Please verify your information and try again."
        );
    }

    throw TracedException(
        "Unexpected response code: Received code '"
        + std::to_string(response_code)
        + "' during RSA key processing."
    );
}

/**
 * @brief Completes the RSA public key exchange after successful registration.
 *
 * @param comm_manager Communication manager used for sending and receiving protocol messages.
 *
 * @details
 * This function generates a fresh RSA key pair, sends the public key to the server,
 * and handles the server response containing the encrypted AES key.
 */
void complete_registration_key_exchange(const CommunicationManager& comm_manager)
{
    RSAPrivateWrapper rsa_key_wrapper;

    send_rsa_public_key(comm_manager, rsa_key_wrapper);

    handle_rsa_key_response(
        comm_manager,
        protocol::response::KEY_SEND_SUCCESS,
        rsa_key_wrapper.getPrivateKey()
    );
}