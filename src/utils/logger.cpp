/**
 * @file logger.cpp
 * @brief Implements exception and stack-trace logging for the backup client.
 *
 * @details
 * This module appends timestamped exception details to the client log file.
 * TracedException instances retain the stack trace captured at their creation
 * point, while other exception types are logged with the current stack trace.
 *
 * @author Tehila Cahnaman
 */

#include "utils/logger.h"

#include <array>
#include <fstream>
#include <iostream>

namespace
{
    /** Date and time format used for log entries. */
    constexpr char LOG_TIME_FORMAT[] = "%Y-%m-%d %H:%M:%S";

    /** Name of the client log file. */
    constexpr char LOG_FILE_NAME[] = "client.log";

    /** Number of characters required by the formatted timestamp, including null termination. */
    constexpr std::size_t TIMESTAMP_BUFFER_SIZE = 20;

    /**
     * @brief Creates a formatted timestamp for the current local time.
     *
     * @return Current local date and time in `YYYY-MM-DD HH:MM:SS` format.
     *
     * @throws std::runtime_error If the local time cannot be obtained or formatted.
     */
    std::string create_timestamp()
    {
        const std::time_t current_time = std::time(nullptr);
        const std::tm* local_time = std::localtime(&current_time);

        if (local_time == nullptr)
        {
            throw std::runtime_error("Failed to obtain the current local time.");
        }

        std::array<char, TIMESTAMP_BUFFER_SIZE> timestamp{};

        if (std::strftime(
                timestamp.data(),
                timestamp.size(),
                LOG_TIME_FORMAT,
                local_time
            ) == 0)
        {
            throw std::runtime_error("Failed to format the log timestamp.");
        }

        return timestamp.data();
    }
}

/**
 * @brief Appends exception details and a stack trace to the client log file.
 *
 * @param exception Exception to log.
 *
 * @details
 * When the exception is a TracedException, the stack trace captured when the
 * exception was created is written to the log. For other exception types, the
 * function records the stack trace from the current logging location.
 *
 * Logging failures are reported to the standard error stream and are not
 * propagated, preventing diagnostic code from masking the original exception.
 */
void log_exception(const std::exception& exception)
{
    std::ofstream log_file(LOG_FILE_NAME, std::ios::app);

    if (!log_file.is_open())
    {
        std::cerr << "Failed to open " << LOG_FILE_NAME << '\n';
        return;
    }

    try
    {
        log_file << '[' << create_timestamp() << "] "
                 << exception.what() << '\n';

        const auto* traced_exception =
            dynamic_cast<const TracedException*>(&exception);

        if (traced_exception != nullptr)
        {
            // Use the construction-time trace to retain the original failure location.
            log_file << "Traceback:\n"
                     << traced_exception->trace()
                     << '\n';
        }
        else
        {
            log_file << "Traceback (logging location):\n"
                     << boost::stacktrace::stacktrace()
                     << '\n';
        }
    }
    catch (const std::exception& logging_error)
    {
        std::cerr << "Failed to write to " << LOG_FILE_NAME
                  << ": " << logging_error.what() << '\n';
    }
}
