/**
 * @file FileAuthentication.cpp
 * @brief Implements encrypted file backup and CRC verification handling.
 *
 * @details
 * This module encrypts files before upload, sends encrypted file chunks to the
 * backup server, validates the server CRC response, and reports upload status.
 * CRC mismatches are retried according to the retry policy defined by
 * FileAuthentication.
 *
 * @author Tehila Cahnaman
 */

#include "crypto/FileAuthentication.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cryptopp/cryptlib.h>

#include "config/client_paths.h"
#include "crypto/AESWrapper.h"
#include "protocol/request.h"
#include "registration/client_credentials.h"
#include "ui/console_ui.h"
#include "utils/input_validation.h"
#include "utils/logger.h"

namespace fs = std::filesystem;

namespace
{
    /** @brief Defines the size of one mebibyte (MiB) in bytes */
    constexpr std::size_t ONE_MIB = 1024 * 1024;

    /**
     * @brief Calculates the fixed payload size used by file-backup requests.
     *
     * @return Fixed request payload size in bytes, excluding encrypted chunk data.
     */
    payload_size_t get_file_backup_payload_size()
    {
        return USERNAME_LEN + RSA_KEY_LEN
               + sizeof(enc_chunk_size_t)
               + sizeof(file_size_t)
               + sizeof(packet_num_t)
               + sizeof(total_packets_t)
               + FILE_NAME_LEN;
    }

    /**
     * @brief Prints an upload progress update.
     *
     * @param percent Upload completion percentage.
     */
    void print_upload_progress(std::size_t percent)
    {
        std::cout << Color::YELLOW
                  << percent << "% completed."
                  << Color::RESET << '\n';
    }
}

/**
 * @brief Constructs a file authentication handler.
 *
 * @param comm_manager Communication manager used for protocol requests and responses.
 */
FileAuthentication::FileAuthentication(CommunicationManager& comm_manager)
    : comm_manager_(comm_manager)
{
}

/**
 * @brief Determines the chunk size to be used for processing a file based on its size.
 *
 * For files smaller than one mebibyte (1 MiB), a smaller chunk size is returned.
 * For files equal to or larger than 1 MiB, a larger chunk size is returned.
 *
 * @param file_size The size of the file in bytes.
 * @return The chunk size to be used, either SMALL_CHUNK_SIZE or LARGE_CHUNK_SIZE.
 */
std::size_t FileAuthentication::get_chunk_size(std::size_t file_size)
{
    if (file_size < ONE_MIB)
    {
        return SMALL_CHUNK_SIZE;
    }

    return LARGE_CHUNK_SIZE;
}

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
std::vector<char> FileAuthentication::encrypt_file(
    const std::filesystem::path& file_path,
    const std::string& file_name,
    std::size_t& file_size,
    std::vector<char>& file_data
)
{
    std::ifstream file_stream(file_path, std::ios::binary);

    if (!file_stream.is_open())
    {
        throw TracedException("Failed to open " + file_name);
    }

    file_stream.seekg(0, std::ios::end);

    const std::streampos end_position = file_stream.tellg();
    if (end_position < 0)
    {
        throw TracedException("Failed to determine file size for " + file_name);
    }

    file_size = static_cast<std::size_t>(end_position);

    if (file_size > MAX_FILE_SIZE)
    {
        throw ClientException(
            "File too large. The maximum allowed file size is "
            + std::to_string(MAX_FILE_SIZE)
            + " bytes."
        );
    }

    file_stream.seekg(0, std::ios::beg);

    file_data.resize(file_size);
    file_stream.read(file_data.data(), static_cast<std::streamsize>(file_size));

    if (!file_stream && file_stream.gcount() != static_cast<std::streamsize>(file_size))
    {
        throw TracedException("Failed to read full file content from " + file_name);
    }

    const std::string aes_key = load_aes_key(AES_KEY_FILE);
    AESWrapper aes(
        reinterpret_cast<const unsigned char*>(aes_key.data()),
        static_cast<unsigned int>(aes_key.size())
    );

    const std::string encrypted_file =
        aes.encrypt(file_data.data(), static_cast<unsigned int>(file_data.size()));

    return {encrypted_file.begin(), encrypted_file.end()};
}

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
void FileAuthentication::send_encrypted_file_request(
    const std::filesystem::path& file_path,
    const std::string& file_name,
    std::vector<char>& file_data
)
{
    std::size_t file_size = 0;
    const std::vector<char> encrypted_file =
        encrypt_file(file_path, file_name, file_size, file_data);

    Request request;
    const std::string user_id = load_user_id(CL_INFO_FILE);

    request.get_header().set_user_id(user_id);
    request.get_header().set_request_code(protocol::request::CREATE_BACKUP);

    request.get_payload().set_file_size(static_cast<file_size_t>(file_size));
    request.get_payload().set_file_name(file_name);

    const std::size_t chunk_size = get_chunk_size(file_size);
    const std::size_t total_packets =
        (encrypted_file.size() + chunk_size - 1) / chunk_size;

    request.get_payload().set_total_packets(
        static_cast<total_packets_t>(total_packets)
    );

    std::size_t printed_percent = 0;

    for (std::size_t packet = 1; packet <= total_packets; ++packet)
    {
        const std::size_t start_offset = (packet - 1) * chunk_size;
        const std::size_t current_chunk_size =
            std::min(chunk_size, encrypted_file.size() - start_offset);

        request.get_payload().set_packet_number(
            static_cast<packet_num_t>(packet)
        );

        request.get_payload().set_encrypted_chunk_size(
            static_cast<enc_chunk_size_t>(current_chunk_size)
        );

        request.get_payload().set_encrypted_chunk_data(
            {
                encrypted_file.begin() + static_cast<std::ptrdiff_t>(start_offset),
                encrypted_file.begin() + static_cast<std::ptrdiff_t>(
                    start_offset + current_chunk_size
                )
            }
        );

        request.get_header().set_payload_size(
            get_file_backup_payload_size()
            + static_cast<payload_size_t>(current_chunk_size)
        );

        if (!crc_error_)
        {
            const std::size_t percent = (FULL_PERCENT * packet) / total_packets;

            if (percent >= printed_percent + PROGRESS_STEP_PERCENT
                || packet == total_packets)
            {
                printed_percent =
                    (percent / PROGRESS_STEP_PERCENT) * PROGRESS_STEP_PERCENT;

                if (packet == total_packets)
                {
                    printed_percent = FULL_PERCENT;
                }

                print_upload_progress(printed_percent);
            }
        }

        comm_manager_.send_request(request);
    }

    encrypted_file_size_ = request.get_payload().get_encrypted_file_size();
}


/**
 * @brief Verifies the CRC (Cyclic Redundancy Check) response received from the server for an uploaded file.
 *
 * This method evaluates the integrity and validity of the server's response to a file upload. It compares
 * the expected CRC checksum, file size, and user ID based on the file data provided.
 *
 * @param file_data A vector of characters representing the uploaded file data to validate the CRC checksum.
 *
 * @return True if the CRC verification succeeds, otherwise false. Returns false if there are checksum
 *         or encrypted size mismatches, which marks the internal CRC error state as true.
 *
 * @throws TracedException If the server returns a failed response, a user ID mismatch, or an unexpected response code.
 * @throws ClientException If the server rejects the upload because it exceeds the allowed size limit.
 */
bool FileAuthentication::verify_upload_crc_response(const std::vector<char>& file_data)
{
    const Response response = comm_manager_.receive_response();
    const code_t response_code = response.get_header().get_response_code();

    if (response_code == protocol::response::FAILED)
    {
        throw TracedException("Server error: CRC verification failed.");
    }

    if (response_code == protocol::response::UPLOAD_REJECTED_TOO_LARGE)
    {
        throw ClientException("Upload rejected. File must not exceed the allowed limit.");
    }

    const std::string user_id = load_user_id(CL_INFO_FILE);

    if (user_id != response.get_payload().get_user_id())
    {
        throw TracedException("User ID mismatch during CRC verification.");
    }

    if (response_code != protocol::response::UPLOAD_RECEIVED)
    {
        throw TracedException(
            "Unexpected response code during CRC verification: "
            + std::to_string(response_code)
        );
    }

    const checksum_t expected_checksum =
        calculate_crc32(file_data.data(), file_data.size());

    const bool checksum_mismatch =
        response.get_payload().get_checksum() != expected_checksum;

    const bool encrypted_size_mismatch =
        response.get_payload().get_encrypted_file_size() != encrypted_file_size_;

    if (checksum_mismatch || encrypted_size_mismatch)
    {
        crc_error_ = true;
        return false;
    }

    crc_error_ = false;
    return true;
}

/**
 * @brief Sends the upload CRC status to the server.
 *
 * @param file_name File name associated with the CRC result.
 * @param op_code CRC status operation code.
 */
void FileAuthentication::send_crc_status_request(
    const std::string& file_name,
    std::uint16_t op_code
) const
{
    Request request;
    const std::string user_id = load_user_id(CL_INFO_FILE);

    request.get_header().set_user_id(user_id);
    request.get_header().set_request_code(op_code);
    request.get_header().set_payload_size(get_file_backup_payload_size());

    request.get_payload().set_file_name(file_name);

    comm_manager_.send_request(request);
}

/**
 * @brief Validates the server acknowledgment (ACK) response received from a communication manager.
 *
 * This method processes the server's ACK response by performing the following validations:
 * 1. Ensures the received response code does not indicate a failure.
 * 2. Verifies that the user ID in the response payload matches the locally loaded user ID.
 * 3. Checks that the response code matches the expected ACK code.
 *
 * This method is essential for ensuring the integrity and consistency of ACK responses during
 * communication exchange.
 *
 * @throws TracedException if the server response code indicates failure.
 * @throws TracedException if there is a mismatch between the user IDs.
 * @throws TracedException if the response code is not the expected ACK code.
 */
void FileAuthentication::process_srv_ack_response() const
{
    const Response response = comm_manager_.receive_response();
    const std::string user_id = load_user_id(CL_INFO_FILE);
    const code_t response_code = response.get_header().get_response_code();

    if (response_code == protocol::response::FAILED)
    {
        throw TracedException("Server ACK failure.");
    }

    if (user_id != response.get_payload().get_user_id())
    {
        throw TracedException("User ID mismatch during ACK validation.");
    }

    if (response_code != protocol::response::ACK)
    {
        throw TracedException(
            "Unexpected ACK response code: " + std::to_string(response_code)
        );
    }
}

/**
 * @brief Backs up one file and retries upload on CRC mismatch.
 *
 * @param file_path Path to the file to back up.
 * @param file_name File name to include in the protocol payload.
 *
 * @details
 * The function uploads the encrypted file, waits for the server CRC response,
 * sends the matching CRC status request, and waits for the final ACK. Retryable
 * CRC mismatches are retried up to CRC_TRIALS_COUNT.
 */
void FileAuthentication::backup_file(
    const std::filesystem::path& file_path,
    const std::string& file_name
)
{
    std::vector<char> file_data;
    std::size_t crc_failures = 0;

    while (true)
    {
        send_encrypted_file_request(file_path, file_name, file_data);

        if (verify_upload_crc_response(file_data))
        {
            send_crc_status_request(file_name, protocol::request::CRC_SUCCESS);
            process_srv_ack_response();

            std::cout << Color::GREEN
                      << "File " << file_name << " sent successfully!"
                      << Color::RESET << std::endl;
            break;
        }

        ++crc_failures;

        if (crc_failures == CRC_TRIALS_COUNT)
        {
            send_crc_status_request(file_name, protocol::request::CRC_FAILURE);
            process_srv_ack_response();

            std::cout << Color::RED
                      << "Failed to upload " << file_name
                      << " after three attempts."
                      << Color::RESET << std::endl;
            break;
        }

        send_crc_status_request(file_name, protocol::request::CRC_ERROR);
    }
}

/**
 * @brief Backs up a collection of files from a selected directory.
 *
 * @param dir_name Directory containing the files to back up.
 * @param files File names selected for backup.
 *
 * @details
 * Each file name is validated before upload. Invalid or missing files are
 * reported to the user and skipped.
 */
void FileAuthentication::backup_files(
    const std::string& dir_name,
    const std::vector<std::string>& files
)
{
    const fs::path dir_path(dir_name);

    for (const std::string& file_name : files)
    {
        const fs::path file_path = dir_path / file_name;

        if (!is_valid_filename(file_name))
        {
            std::cout << Color::RED
                      << "Invalid file name: " << file_name
                      << Color::RESET << std::endl;
            continue;
        }

        if (!fs::exists(file_path))
        {
            std::cout << Color::RED
                      << "File not found: " << file_name
                      << Color::RESET << std::endl;
            continue;
        }

        try
        {
            backup_file(file_path, file_name);
        }
        catch (ClientException& e) {
            std::cout << Color::RED << e.what() << Color::RESET << std::endl;
        }
    }
}
