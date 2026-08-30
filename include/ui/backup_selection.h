/**
 * @file backup_selection.h
 * @brief Declares console prompts for selecting backup targets.
 *
 * @details
 * This module exposes user-input helpers for selecting a backup directory and
 * the list of files to back up.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <string>
#include <vector>

/**
 * @brief Prompts the user for the directory containing files to back up.
 *
 * @return Valid directory name.
 */
std::string prompt_backup_directory();

/**
 * @brief Prompts the user for file names to back up.
 *
 * @return Vector of selected file names.
 */
std::vector<std::string> prompt_files_to_backup();
