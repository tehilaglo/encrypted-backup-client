/**
 * @file logger.h
 * @brief Declares exception tracing and application logging utilities.
 *
 * @details
 * This module provides an exception type that captures a Boost stack trace at
 * construction time, along with a logging function that records exceptions,
 * timestamps, and diagnostic stack traces in the client log file.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <exception>
#include <stdexcept>
#include <string>

#include <boost/stacktrace.hpp>

/**
 * @class TracedException
 * @brief Runtime exception that captures its construction-time stack trace.
 *
 * @details
 * TracedException extends std::runtime_error and stores a Boost stack trace at
 * the point where the exception object is created. This allows the logger to
 * preserve the original failure context after stack unwinding has begun.
 */
class TracedException : public std::runtime_error
{
public:
    /**
     * Stored publicly for compatibility with the existing interface.
     * Prefer accessing it through trace().
     */
    boost::stacktrace::stacktrace trace_;

    explicit TracedException(const std::string& message)
        : std::runtime_error(message),
          trace_(boost::stacktrace::stacktrace())
    {
    }

    const boost::stacktrace::stacktrace& trace() const
    {
        return trace_;
    }
};

/**
 * @brief Appends exception details and a stack trace to the client log file.
 *
 * @param exception Exception to log.
 */
void log_exception(const std::exception& exception);
