/**
 * @file console_ui.h
 * @brief Defines ANSI escape sequences used for console text formatting.
 *
 * @details
 * The Color class provides reusable ANSI escape sequences for applying colors
 * and text styles to terminal output. These values are intended for terminals
 * that support ANSI formatting.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <string_view>

/**
 * @class Color
 * @brief Provides ANSI terminal color and text-style escape sequences.
 *
 * @details
 * All values are compile-time string views and may be written directly to
 * standard output streams. RESET should be emitted after formatted text to
 * restore the terminal's default appearance.
 */
class Color
{
public:
     static constexpr std::string_view RED = "\033[91m";
     static constexpr std::string_view GREEN = "\033[92m";
     static constexpr std::string_view YELLOW = "\033[93m";
     static constexpr std::string_view BLUE = "\033[94m";
     static constexpr std::string_view PURPLE = "\033[95m";
     static constexpr std::string_view CYAN = "\033[96m";

     static constexpr std::string_view BOLD = "\033[1m";
     static constexpr std::string_view UNDERLINE = "\033[4m";

     static constexpr std::string_view RESET = "\033[0m";
};
