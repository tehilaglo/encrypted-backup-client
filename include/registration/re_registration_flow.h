/**
* @file re_registration_flow.h
 * @brief Declares the client re-registration flow.
 *
 * @details
 * This module exposes the re-registration entry point used when a local client
 * information file already exists. The flow validates existing credentials with
 * the server and refreshes the AES key through the RSA key-exchange handler.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include "core/CommunicationManager.h"

/**
 * @brief Handles re-registration for a previously registered client.
 *
 * @param comm_manager Communication manager used for server communication.
 */
void client_re_registration(const CommunicationManager& comm_manager);