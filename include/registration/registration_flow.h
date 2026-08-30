/**
* @file registration_flow.h
 * @brief Declares the client registration flow.
 *
 * @details
 * This module exposes the registration entry point used when no existing
 * client information file is available. The registration flow sends the
 * requested username to the server, stores the returned user ID, and completes
 * the RSA/AES key exchange process.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include "core/CommunicationManager.h"

/**
 * @brief Runs the full client registration flow.
 *
 * @param comm_manager Communication manager used for server communication.
 *
 * @throws ClientException for user-facing registration errors.
 * @throws TracedException for unexpected server, protocol, or file errors.
 */
void client_registration(const CommunicationManager& comm_manager);
