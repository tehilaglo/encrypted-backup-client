/**
 * @file CommunicationManager.cpp
 * @brief Implements client-side TCP request sending and response receiving.
 *
 * @details
 * This module handles the transport layer for the client protocol. Requests are
 * serialized by the Request class before being sent, and responses are received
 * as raw bytes before being deserialized by the Response class.
 *
 * @author Tehila Cahnaman
 */

#include "core/CommunicationManager.h"

#include <boost/asio.hpp>
#include <boost/system/system_error.hpp>

#include <vector>

namespace
{
    /** Represents the total size of the response header in bytes */
    constexpr std::size_t RESPONSE_HEADER_SIZE =
        sizeof(version_t) + sizeof(code_t) + sizeof(payload_size_t);

    /** Offset within the response header where the payload size field begins */
    constexpr std::size_t PAYLOAD_SIZE_FIELD_OFFSET =
        sizeof(version_t) + sizeof(code_t);
}

/**
 * @brief Constructs a communication manager around an existing TCP socket.
 *
 * @param socket Connected TCP socket used for client/server communication.
 */
CommunicationManager::CommunicationManager(boost::asio::ip::tcp::socket& socket)
    : socket_(socket)
{
}

/**
 * @brief Serializes and sends a request to the server.
 *
 * @param request Request object to serialize and send.
 *
 * @throws boost::system::system_error If writing to the socket fails.
 */
void CommunicationManager::send_request(const Request& request) const
{
    const std::vector<char> serialized_request = request.serialize();

    boost::system::error_code error;
    boost::asio::write(socket_, boost::asio::buffer(serialized_request), error);

    if (error)
    {
        throw boost::system::system_error(
            error,
            "Failed to send request to the server"
        );
    }
}

/**
 * @brief Receives and deserializes a response from the server.
 *
 * @return Parsed Response object.
 *
 * @throws boost::system::system_error If reading the response header or payload fails.
 */
Response CommunicationManager::receive_response() const
{
    boost::system::error_code error;

    std::vector<char> header_buffer(RESPONSE_HEADER_SIZE);
    boost::asio::read(socket_, boost::asio::buffer(header_buffer), error);

    if (error)
    {
        throw boost::system::system_error(
            error,
            "Failed to read response header from the server"
        );
    }

    payload_size_t net_payload_size = 0;
    std::memcpy(
        &net_payload_size,
        header_buffer.data() + PAYLOAD_SIZE_FIELD_OFFSET,
        sizeof(net_payload_size)
    );

    const payload_size_t payload_size = ntohl(net_payload_size);

    std::vector<char> payload_buffer(payload_size);
    if (payload_size > 0)
    {
        boost::asio::read(socket_, boost::asio::buffer(payload_buffer), error);

        if (error)
        {
            throw boost::system::system_error(
                error,
                "Failed to read response payload from the server"
            );
        }
    }

    // Response::deserialize expects a contiguous buffer containing both the
    // protocol header and the payload bytes.
    std::vector<char> response_buffer;
    response_buffer.reserve(header_buffer.size() + payload_buffer.size());

    response_buffer.insert(
        response_buffer.end(),
        header_buffer.begin(),
        header_buffer.end()
    );

    response_buffer.insert(
        response_buffer.end(),
        payload_buffer.begin(),
        payload_buffer.end()
    );

    return Response::deserialize(response_buffer);
}
