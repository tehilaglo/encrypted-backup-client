/**
 * @file CommunicationManager.h
 * @brief Declares the client-side TCP communication manager.
 *
 * @details
 * The CommunicationManager class owns the client-side request/response transport
 * logic. It serializes outgoing protocol requests, sends them over an existing
 * TCP socket, receives binary server responses, and delegates response parsing
 * to the Response model.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <boost/asio/ip/tcp.hpp>

#include "protocol/request.h"
#include "protocol/response.h"


/**
 * @brief Manages communication between a client and a server using a TCP socket.
 *
 * The CommunicationManager class provides methods to send requests and
 * receive responses over a Boost.Asio TCP socket. It abstracts the
 * underlying serialization and deserialization of data, ensuring reliable
 * communication with the server.
 */
class CommunicationManager
{
public:

    /**
    * @brief Constructs a CommunicationManager object using the specified socket.
    *
    * @param socket The TCP socket to be used for communication. This socket
    *               is referenced and managed by the CommunicationManager for
    *               sending and receiving data.
    *
    * @return A CommunicationManager object initialized with the given socket.
    */
    explicit CommunicationManager(boost::asio::ip::tcp::socket& socket);

    /**
     * @brief Sends a serialized request to the server over the associated TCP socket.
     *        The method serializes the provided request and writes it to the socket.
     *
     * @param request The request object to be serialized and sent to the server.
     * @throws boost::system::system_error if the request could not be sent due to a socket error.
     */
    void send_request(const Request& request) const;

    /**
     * @brief Receives a response from the server over the TCP socket.
     *
     * @throws boost::system::system_error if an error occurs while reading
     *         the header or payload data from the socket.
     *
     * @return The deserialized `Response` object containing the server's response.
     */
    Response receive_response() const;


private:
    /** Represents a reference to a Boost.Asio TCP socket used for network communication */
    boost::asio::ip::tcp::socket& socket_;
};
