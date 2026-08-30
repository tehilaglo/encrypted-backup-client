/*
#include <iostream>
#include <iomanip>
#include <string>

#include "protocol/request.h"
#include "protocol/response.h"


class ResponseHeader;
class RequestHeader;
// Define the << operator overloads here
std::ostream& operator<<(std::ostream& os, const RequestHeader& header) {
    os << "RequestHeader: { "
       << "user_id: " << header.get_user_id()  << ", "
       << "version: " << header.get_version() << ", "
       << "request_code: " << header.get_request_code() << ", "
       << "payload_size: " << header.get_payload_size()
       << " }";
    return os;
}

std::ostream& operator<<(std::ostream& os, const ResponseHeader& header) {
    os << "ResponseHeader: { "
       << "version: " << header.get_version() << ", "
       << "response_code: " << header.get_response_code() << ", "
       << "payload_size: " << header.get_payload_size()
       << " }";
    return os;
}

std::ostream& operator<<(std::ostream& os, const RequestPayload& payload) {
    os << "RequestPayload: { "
       << "username: " << payload.get_username() << ", "
       << "public_key: " << payload.get_public_key() << ", "
       << "encrypted_file_size: " << payload.get_encrypted_file_size() << ", "
       << "orig_file_size: " << payload.get_file_size() << ", "
       << "packet_number: " << payload.get_packet_number() << ", "
       << "total_packets: " << payload.get_total_packets() << ", "
       << "file_name: " << payload.get_file_name() << ", "
       << "encrypted_file_data: ";
    return os;
}

std::ostream& operator<<(std::ostream& os, const ResponsePayload& payload) {
    os << "ResponsePayload: { "
       << "user_id: " << payload.get_user_id() << ", "
       << "encrypted_aes_key: " << std::string(payload.get_encrypted_aes_key().data(), payload.get_encrypted_aes_key().size())  << ", "
       << "encrypted_file_size: " << payload.get_encrypted_file_size() << ", "
       << "file_name: " << payload.get_file_name() << ", "
       << "checksum: " << payload.get_checksum()
       << " }";
    return os;
}

std::ostream& operator<<(std::ostream& os, const Request& request) {
    os << "Request: { "
       << request.get_header() << ", "
       << request.get_payload()
       << " }";
    return os;
}

std::ostream& operator<<(std::ostream& os, const Response& response) {
    os << "Response: { "
       << response.get_header() << ", "
       << response.get_payload()
       << " }";
    return os;
}

void hexify(const char* buffer, size_t start, size_t end) {
    if (start >= end) {
        std::cerr << "Invalid range!" << std::endl;
        return;
    }

    // Save the current flags (to restore later)
    std::ios::fmtflags f(std::cout.flags());
    std::cout << std::hex;  // Set output to hexadecimal

    // Print each byte in the range as hexadecimal
    for (size_t i = start; i < end; ++i) {
        // Print byte in hex format with 2 characters (e.g., '0x08' -> '08')
        std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]);

        // Print a newline every 16 bytes, otherwise a space
        std::cout << (((i - start + 1) % 16 == 0) ? "\n" : " ");
    }

    std::cout << std::endl;  // Ensure a newline at the end
    std::cout.flags(f);  // Restore the original flags
}
*/
