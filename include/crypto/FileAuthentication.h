/**
 * @file FileAuthentication.h
 * @brief Declares encrypted file backup and CRC verification handling.
 *
 * @details
 * This module declares the FileAuthentication class, which manages the
 * client-side encrypted file backup flow. It encrypts selected files, sends
 * them to the backup server in protocol chunks, validates server CRC responses,
 * and reports the final upload status.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "core/CommunicationManager.h"
#include "protocol/protocol_types.h"


/**
 * @class FileAuthentication
 * @brief Provides functionality for secure file backup and communication with a server.
 *
 * This class handles the encryption, backup, and secure transfer of files to a server. It includes
 * capabilities for chunk-based processing, CRC verification, and network communication, ensuring
 * data integrity during file uploads. The implementation uses an AES-based encryption mechanism
 * and retry logic for CRC mismatches, while managing communication via a provided CommunicationManager instance.
 */
class FileAuthentication
{
public:
    /**
    * @brief Constructs a file authentication handler.
    *
    * @param comm_manager Communication manager used for protocol requests and responses.
    */
    explicit FileAuthentication(CommunicationManager& comm_manager);

    /**
     * @brief Backs up one file and retries upload on CRC mismatch.
     *
     * @param file_path Path to the file to back up.
     * @param file_name File name to include in the protocol payload.
     *
     */
    void backup_file(const std::filesystem::path& file_path,
                     const std::string& file_name);

    /**
     * @brief Backs up a collection of files from a selected directory.
     *
     * @param dir_name Directory containing the files to back up.
     * @param files File names selected for backup.
     */
    void backup_files(const std::string& dir_name,
                      const std::vector<std::string>& files);

private:

    /**
    * Defines the size, in bytes, of a small data chunk used for operations
    * that process data in smaller, manageable segments.
    * Commonly used in scenarios such as file processing or network transmission.
    */
    static constexpr std::size_t SMALL_CHUNK_SIZE = 4 * 1024;

    /**
     * Defines the size of a large data chunk used for processing or transferring
     * substantial amounts of data efficiently. This value represents the number
     * of bytes in a single chunk, optimized for performance in bulk operations.
     */
    static constexpr std::size_t LARGE_CHUNK_SIZE = 64 * 1024;

    /**
     * Defines the step size, in percentage increments, used for tracking or displaying progress.
     * Useful for operations that require regular updates on completion status, such as file uploads
     * or data processing tasks.
     */
    static constexpr std::size_t PROGRESS_STEP_PERCENT = 10;

    /**
     * Represents the percentage value for a fully completed operation or state.
     * Commonly used as a reference for conditions or calculations requiring 100% completion.
     */
    static constexpr std::size_t FULL_PERCENT = 100;

    /**
     * Defines the maximum number of retry attempts allowed for verifying
     * the CRC (Cyclic Redundancy Check) during file upload operations.
     */
    static constexpr std::size_t CRC_TRIALS_COUNT = 3;

    /**
     * @brief Determines the chunk size to be used for processing a file based on its size.
     *
     * @param file_size The size of the file in bytes.
     * @return The chunk size to be used, either SMALL_CHUNK_SIZE or LARGE_CHUNK_SIZE.
     */
    static std::size_t get_chunk_size(std::size_t file_size);

    /**
     * @brief Reads and encrypts a file using the locally stored AES key.
     *
     * @param file_path Path to the file to encrypt.
     * @param file_name Display/protocol file name used for error messages.
     * @param file_size Output parameter that receives the original file size.
     * @param file_data Output parameter that receives the original file bytes.
     *
     * @return Encrypted file bytes.
     *
     * @throws ClientException if the file exceeds the allowed protocol size.
     * @throws TracedException if the file cannot be opened, sized, or read.
     */
    static std::vector<char> encrypt_file(const std::filesystem::path& file_path,
                                          const std::string& file_name,
                                          std::size_t& file_size,
                                          std::vector<char>& file_data);

    /**
     * @brief Encrypts a file and sends it to the server in protocol chunks.
     *
     * @param file_path Path to the file to upload.
     * @param file_name File name to include in the protocol payload.
     * @param file_data Output parameter that receives the original file bytes for CRC validation.
     *
     * @throws ClientException for user-facing file validation failures.
     * @throws TracedException for file, credential, or protocol errors.
     */
    void send_encrypted_file_request(const std::filesystem::path& file_path,
                                     const std::string& file_name,
                                     std::vector<char>& file_data);

    /**
     * @brief Verifies the CRC (Cyclic Redundancy Check) response received from the server for an uploaded file.
     *
     * @param file_data A vector of characters representing the uploaded file data to validate the CRC checksum.
     *
     * @return True if the CRC verification succeeds, otherwise false. Returns false if there are checksum
     *         or encrypted size mismatches, which marks the internal CRC error state as true.
     *
     * @throws TracedException If the server returns a failed response, a user ID mismatch, or an unexpected response code.
     * @throws ClientException If the server rejects the upload because it exceeds the allowed size limit.
     */
    bool verify_upload_crc_response(const std::vector<char>& file_data);

    /**
    * @brief Sends the upload CRC status to the server.
    *
    * @param file_name File name associated with the CRC result.
    * @param op_code CRC status operation code.
    */
    void send_crc_status_request(const std::string& file_name,
                                 std::uint16_t op_code) const;

    /**
     * @brief Validates the server acknowledgment (ACK) response received from a communication manager.
     *
     * @throws TracedException if the server response code indicates failure.
     * @throws TracedException if there is a mismatch between the user IDs.
     * @throws TracedException if the response code is not the expected ACK code.
     */
    void process_srv_ack_response() const;


    /**
     * Reference to the CommunicationManager responsible for managing
     * all communication-related operations, such as sending and receiving
     * messages, handling network protocols, and ensuring data transmission
     * reliability throughout the system.
     */
    CommunicationManager& comm_manager_;

    /**
     * Represents the size of the encrypted file in chunks. Used to track the total
     * encrypted file size during processing or upload operations.
     */
    enc_chunk_size_t encrypted_file_size_{0};

    /**
     * Represents the state of a CRC (Cyclic Redundancy Check) error.
     * This variable is used to indicate whether a CRC verification error
     * has been detected during operations such as file transfers or data integrity checks.
     */
    bool crc_error_{false};
};
