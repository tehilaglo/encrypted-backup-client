# ==============================================================================
# Encrypted Backup Client - Test Build Configuration
#
# Configures the Catch2-based test executable for protocol serialization,
# deserialization, validation, encoding utilities, and file authentication.
#
# Catch2 v3 is used from the local environment when available. Otherwise,
# CMake FetchContent downloads the pinned version automatically.
#
# @author Tehila Cahnaman
# ==============================================================================

include(FetchContent)


# ------------------------------------------------------------------------------
# Catch2
# ------------------------------------------------------------------------------

# Prefer an existing Catch2 v3 installation.
find_package(Catch2 3 QUIET)

# Fall back to the pinned Catch2 release when it is not installed locally.
if(NOT Catch2_FOUND)
    FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.6.0
    )

    FetchContent_MakeAvailable(Catch2)
endif()


# ------------------------------------------------------------------------------
# Test executable
# ------------------------------------------------------------------------------

add_executable(
        protocol_tests
        test_file_authentication.cpp
        test_request_serialization.cpp
        test_response_deserialization.cpp
        test_response_malformed.cpp
        test_protocol_fields.cpp
        test_encoding_utils.cpp
        test_protocol_codes.cpp
)

target_include_directories(
        protocol_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
)

target_compile_options(
        protocol_tests PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

# Catch2WithMain provides the Catch2 test runner, while client_core exposes the
# production implementation exercised by the tests.
target_link_libraries(
        protocol_tests PRIVATE
        Catch2::Catch2WithMain
        client_core
)


# ------------------------------------------------------------------------------
# CTest registration
# ------------------------------------------------------------------------------

# Register the Catch2 test executable with CTest so the complete suite can be
# executed through `ctest`.
add_test(
        NAME protocol_tests
        COMMAND protocol_tests
)
