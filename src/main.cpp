/**
 * @file main.cpp
 * @brief Entry point for the encrypted backup client.
 *
 * @details
 * This module starts the client workflow, handles top-level exceptions,
 * performs graceful disconnection on failure, and removes the temporary AES key
 * file before exiting.
 *
 * @author Tehila Cahnaman
 */

#include <exception>
#include <filesystem>
#include <iostream>

#include "config/client_paths.h"
#include "core/ClientHandler.h"
#include "ui/console_ui.h"
#include "utils/input_validation.h"
#include "utils/logger.h"

namespace fs = std::filesystem;

namespace
{
    /**
     * @brief Removes the temporary AES key file if it exists.
     *
     * @details
     * The AES key is stored locally only while the client is running. This helper
     * performs best-effort cleanup during normal shutdown.
     */
    void cleanup_temporary_aes_key()
    {
        const fs::path aes_key_path = get_aes_key_path();

        if (fs::exists(aes_key_path))
        {
            fs::remove(aes_key_path);
        }
    }

    /**
     * @brief Logs an exception, disconnects the client, and prints an error message.
     *
     * @param client_handler Client workflow coordinator.
     * @param exception Exception that was caught.
     * @param message User-facing error message.
     */
    void handle_startup_failure(ClientHandler& client_handler,
                                const std::exception& exception,
                                const std::string& message)
    {
        log_exception(exception);
        client_handler.disconnect();

        std::cerr << message << std::endl;
    }
}

/**
 * @brief Runs the encrypted backup client application.
 *
 * @return 0 on application exit.
 */
int main()
{
    ClientHandler client_handler;

    try
    {
        client_handler.run();
    }
    catch (const ClientException& exception)
    {
        handle_startup_failure(
            client_handler,
            exception,
            std::string(Color::RED) + exception.what() + std::string(Color::RESET)
        );
    }
    catch (const std::exception& exception)
    {
        handle_startup_failure(
            client_handler,
            exception,
            "Hmm... Something seems to have gone wrong."
        );
    }

    cleanup_temporary_aes_key();

    return 0;
}
