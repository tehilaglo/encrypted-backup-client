/**
 * @file protocol_codes.h
 * @brief Defines request and response operation codes for the backup protocol.
 *
 * @details
 * This header contains the numeric operation and status codes exchanged between
 * the encrypted backup client and server. Request codes identify actions sent
 * by the client, while response codes describe the result returned by the server.
 *
 * These values form part of the network protocol and must remain synchronized
 * with the corresponding server-side definitions.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include "protocol_types.h"

namespace protocol
{
    /**
     * @namespace protocol::request
     * @brief Contains operation codes sent from the client to the server.
     */
    namespace request
    {
        /** Registers a new client with the server. */
        inline constexpr code_t REGISTRATION = 100;

        /** Sends the client's RSA public key to the server. */
        inline constexpr code_t PUBLIC_KEY_SEND = 101;

        /** Re-registers a previously registered client. */
        inline constexpr code_t RE_REGISTRATION = 102;

        /** Uploads encrypted file data to create a backup. */
        inline constexpr code_t CREATE_BACKUP = 103;

        /** Confirms that the uploaded file passed CRC validation. */
        inline constexpr code_t CRC_SUCCESS = 120;

        /** Reports a CRC mismatch and requests another upload attempt. */
        inline constexpr code_t CRC_ERROR = 121;

        /** Reports that CRC validation failed after all retry attempts. */
        inline constexpr code_t CRC_FAILURE = 122;

        /** Notifies the server that the client is disconnecting. */
        inline constexpr code_t DISCONNECT = 130;
    }

    /**
     * @namespace protocol::response
     * @brief Contains status codes returned from the server to the client.
     */
    namespace response
    {
        /** Indicates that client registration completed successfully. */
        inline constexpr code_t REGISTRATION_SUCCESS = 200;

        /** Indicates that client registration failed. */
        inline constexpr code_t REGISTRATION_FAILED = 201;

        /** Indicates that the requested username is already registered. */
        inline constexpr code_t USERNAME_TAKEN = 202;

        /** Indicates that client re-registration completed successfully. */
        inline constexpr code_t RE_REGISTRATION_SUCCESS = 205;

        /** Indicates that client re-registration failed. */
        inline constexpr code_t RE_REGISTRATION_FAILED = 206;

        /** Indicates that the public-key exchange completed successfully. */
        inline constexpr code_t KEY_SEND_SUCCESS = 210;

        /** Indicates that the uploaded file was received for CRC validation. */
        inline constexpr code_t UPLOAD_RECEIVED = 220;

        /** Indicates that the uploaded file exceeded the permitted size. */
        inline constexpr code_t UPLOAD_REJECTED_TOO_LARGE = 221;

        /** Acknowledges successful processing of a client request. */
        inline constexpr code_t ACK = 230;

        /** Indicates a general server-side operation failure. */
        inline constexpr code_t FAILED = 231;
    }
}
