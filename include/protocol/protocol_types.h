/**
 * @file protocol_types.h
 * @brief Defines shared constants and fixed-width types for the backup protocol.
 *
 * @details
 * This header contains the field sizes, protocol limits, and fixed-width integer
 * aliases shared by the encrypted backup client's request and response models.
 *
 * These definitions form part of the binary communication protocol and must
 * remain synchronized with the corresponding server-side definitions.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <cstddef>
#include <cstdint>

/** Size of a binary client identifier, in bytes. */
inline constexpr std::size_t UNIQUE_ID_LEN = 16;

/** Size of a serialized RSA public key, in bytes. */
inline constexpr std::size_t RSA_KEY_LEN = 160;

/** Size of the symmetric AES key, in bytes. */
inline constexpr std::size_t SYMMETRIC_KEY_LEN = 32;

/** Minimum permitted username length, in characters. */
inline constexpr std::size_t MIN_USERNAME_LEN = 5;

/**
 * Size of the fixed-width username protocol field, in bytes.
 *
 * One byte is reserved for the null terminator when the field is treated as a
 * C-style string.
 */
inline constexpr std::size_t USERNAME_LEN = 64;

/**
 * Size of the fixed-width file-name protocol field, in bytes.
 *
 * One byte is reserved for the null terminator when the field is treated as a
 * C-style string.
 */
inline constexpr std::size_t FILE_NAME_LEN = 255;

/** Maximum permitted unencrypted file size: 20 MiB. */
inline constexpr std::size_t MAX_FILE_SIZE = 20U * 1024U * 1024U;

/** Protocol version field type. */
using version_t = std::uint8_t;

/** Request and response operation-code field type. */
using code_t = std::uint16_t;

/** Serialized payload-size field type. */
using payload_size_t = std::uint32_t;

/** Encrypted file-chunk size field type. */
using enc_chunk_size_t = std::uint32_t;

/** Original file-size field type. */
using file_size_t = std::uint32_t;

/** File-packet sequence-number field type. */
using packet_num_t = std::uint16_t;

/** Total file-packet count field type. */
using total_packets_t = std::uint16_t;

/** CRC checksum field type. */
using checksum_t = std::uint32_t;
