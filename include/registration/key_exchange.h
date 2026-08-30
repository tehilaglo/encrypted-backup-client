/**
 * @file key_exchange.h
 * @brief Declares client-side RSA key exchange helpers.
 *
 * @details
 * This module exposes the functions used to send the client's RSA public key,
 * receive the encrypted AES key from the server, and complete the registration
 * key-exchange flow.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <cstdint>
#include <string>

#include "core/CommunicationManager.h"
#include "crypto/RSAWrapper.h"

/**
 * @brief Sends the client's RSA public key to the server.
 *
 * @param comm_manager Communication manager used to send the request.
 *
 * @param rsa_key_wrapper RSA wrapper containing the generated key pair.
 */
void send_rsa_public_key(const CommunicationManager& comm_manager,
                         RSAPrivateWrapper& rsa_key_wrapper);

/**
 * @brief Handles the server response to an RSA key exchange request.
 *
 * @param comm_manager Communication manager used to receive the response.
 * @param op_code Expected success response code.
 *
 * @param private_key Raw RSA private key used to decrypt the AES key.
 */
void handle_rsa_key_response(const CommunicationManager& comm_manager,
                             uint16_t op_code,
                             const std::string& private_key);

/**
 * @brief Runs the full registration key-exchange flow.
 *
 * @param comm_manager Communication manager used for server communication.
 */
void complete_registration_key_exchange(const CommunicationManager& comm_manager);
