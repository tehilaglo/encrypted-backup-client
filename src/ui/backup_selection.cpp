/**
 * @file backup_selection.cpp
 * @brief Handles user prompts for selecting backup directories and files.
 *
 * @details
 * This module provides console-based input helpers for selecting the directory
 * and file names that should be backed up. It validates directory names, checks
 * that the selected directory exists, and collects file names until the user
 * enters the termination keyword.
 *
 * @author Tehila Cahnaman
 */

#include "ui/backup_selection.h"

#include <boost/algorithm/string.hpp>

#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "ui/console_ui.h"
#include "ui/input_keywords.h"
#include "utils/input_validation.h"

/** Defines the keyword used to terminate input */
constexpr auto END_KEYWORD = "done";

namespace {
    /**
     * @brief Clears the rest of the current input line.
     *
     * @details
     * This is useful after using `std::cin >> value`, because the trailing newline
     * may otherwise be consumed by the next `std::getline()` call.
     */
    void discard_remaining_input_line()
    {
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
}

/**
 * @brief Prompts the user for a backup directory and validates it.
 *
 * @return Valid directory name entered by the user.
 *
 * @throws UserCancelledException if the user enters `quit` or closes the input stream.
 */
std::string prompt_backup_directory()
{
    while (true)
    {
        std::string dir_name;

        std::cout << Color::GREEN
                  << "Please enter the directory you want to back up."
                  << std::endl
                  << "Type '" << CANCEL_KEYWORD << "' to cancel:"
                  << Color::RESET << std::endl;

        if (!(std::cin >> dir_name))
        {
            throw UserCancelledException("Backup cancelled.");
        }

        discard_remaining_input_line();
        boost::trim(dir_name);

        if (dir_name == CANCEL_KEYWORD)
        {
            throw UserCancelledException("Backup cancelled.");
        }

        try {
            if (!is_valid_dir_name(dir_name))
            {
                throw ClientException("Invalid directory name: " + dir_name);
            }

            const std::filesystem::path dir_path(dir_name);

            if (!std::filesystem::exists(dir_path) || !std::filesystem::is_directory(dir_path))
            {
                throw ClientException("Directory not found: " + dir_name);
            }

            return dir_name;
        }
        catch (const ClientException& exception)
        {
            std::cerr << Color::RED
                      << exception.what()
                      << " Please try again."
                      << Color::RESET << std::endl;
        }
    }
}

/**
 * @brief Prompts the user for file names to back up.
 *
 * @return Vector of file names entered by the user.
 *
 * @details
 * The user may enter one file name per line. Input collection ends when the user
 * enters `done`. Entering `quit` or closing the input stream cancels the backup.
 *
 * @throws UserCancelledException if the user enters `quit` or closes the input stream.
 */
std::vector<std::string> prompt_files_to_backup()
{
    while (true)
    {
        std::vector<std::string> file_names;
        std::string user_input;

        std::cout << Color::GREEN
                  << "Please enter the file names you want to back up, one per line."
                  << std::endl
                  << "Type '" << END_KEYWORD << "' when you are done, or '"
                  << CANCEL_KEYWORD << "' to cancel:"
                  << Color::RESET << std::endl;

        while (std::getline(std::cin, user_input))
        {
            boost::trim(user_input);

            if (user_input == CANCEL_KEYWORD)
            {
                throw UserCancelledException("File selection cancelled.");
            }

            if (user_input == END_KEYWORD)
            {
                break;
            }

            if (!user_input.empty())
            {
                file_names.push_back(user_input);
            }
        }

        if (!std::cin)
        {
            throw UserCancelledException("File selection cancelled.");
        }

        if (!file_names.empty())
        {
            return file_names;
        }

        std::cerr << Color::RED
                  << "No backup files were provided. Please try again."
                  << Color::RESET << std::endl;

    }
}
