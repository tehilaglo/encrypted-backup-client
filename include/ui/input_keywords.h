/**
 * @file input_keywords.h
 * @brief Defines shared console input keywords used by the client.
 *
 * @details
 * Contains user-input commands that control interactive client workflows,
 *
 * @author Tehila Cahnaman
 */

#pragma once

namespace input_keywords
{
    /**
     * @brief Defines the keyword used to cancel an operation.
     */
    inline constexpr auto CANCEL = "quit";

    /**
     * @brief Defines the keyword used to finish file selection
     */
    inline constexpr auto FINISH_SELECTION = "done";
}
