/**
 * @file test_file_authentication.cpp
 * @brief Unit tests for FileAuthentication's pre-upload input validation.
 *
 * @details
 * Verifies that FileAuthentication::backup_files() skips files with invalid
 * names or that do not exist — reporting via stdout rather than throwing —
 * and that it rejects files exceeding MAX_FILE_SIZE with a ClientException.
 * These cases are all rejected before any network I/O occurs, so the fixture's
 * socket is constructed but never connected.
 *
 * @author Tehila Cahnaman
 */

#include <fstream>
#include <iostream>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <catch2/catch_test_macros.hpp>

#include "crypto/FileAuthentication.h"
#include "utils/input_validation.h"

namespace fs = std::filesystem;

namespace
{
    /**
     * @brief Wires up a FileAuthentication instance over an unconnected socket.
     *
     * @details
     * The underlying CommunicationManager requires a live boost::asio socket to
     * construct, but the validation paths under test never reach the network,
     * so the socket is left unconnected.
     */
    class FileAuthenticationFixture
    {
    public:
        FileAuthenticationFixture()
            : socket_(io_context_),
              communication_manager_(socket_),
              file_authentication_(communication_manager_)
        {
        }

        FileAuthentication& get_file_authentication()
        {
            return file_authentication_;
        }

    private:
        boost::asio::io_context io_context_;
        boost::asio::ip::tcp::socket socket_;
        CommunicationManager communication_manager_;
        FileAuthentication file_authentication_;
    };

    /// @brief RAII helper that redirects std::cout into an in-memory buffer for the
    /// duration of its lifetime, restoring the original stream buffer on destruction.
    class ScopedCoutCapture
    {
    public:
        ScopedCoutCapture()
            : original_buffer_(std::cout.rdbuf(output_.rdbuf()))
        {
        }

        ~ScopedCoutCapture()
        {
            std::cout.rdbuf(original_buffer_);
        }

        ScopedCoutCapture(const ScopedCoutCapture&) = delete;
        ScopedCoutCapture& operator=(const ScopedCoutCapture&) = delete;

        std::string str() const
        {
            return output_.str();
        }

    private:
        std::ostringstream output_;
        std::streambuf* original_buffer_;
    };

    /// @brief RAII helper that creates a fresh temporary directory and removes it
    /// (recursively) on destruction, regardless of what tests leave inside it.
    class ScopedTempDirectory
    {
    public:
        explicit ScopedTempDirectory(const std::string& directory_name)
            : path_(fs::temp_directory_path() / directory_name)
        {
            fs::remove_all(path_);
            fs::create_directories(path_);
        }

        ~ScopedTempDirectory()
        {
            fs::remove_all(path_);
        }

        ScopedTempDirectory(const ScopedTempDirectory&) = delete;
        ScopedTempDirectory& operator=(const ScopedTempDirectory&) = delete;

        const fs::path& path() const
        {
            return path_;
        }

    private:
        fs::path path_;
    };
}

TEST_CASE(
    "File authentication skips invalid file names",
    "[file-authentication][validation]"
)
{
    FileAuthenticationFixture fixture;
    ScopedTempDirectory temp_directory("file_auth_invalid_name_test");
    ScopedCoutCapture output;

    REQUIRE_NOTHROW(
        fixture.get_file_authentication().backup_files(
            temp_directory.path().string(),
            {"../secret.txt"}
        )
    );

    REQUIRE(
        output.str().find("Invalid file name: ../secret.txt")
        != std::string::npos
    );
}

TEST_CASE(
    "File authentication skips files that do not exist",
    "[file-authentication][validation]"
)
{
    FileAuthenticationFixture fixture;
    ScopedTempDirectory temp_directory("file_auth_missing_file_test");
    ScopedCoutCapture output;

    REQUIRE_NOTHROW(
        fixture.get_file_authentication().backup_files(
            temp_directory.path().string(),
            {"missing.bin"}
        )
    );

    REQUIRE(
        output.str().find("File not found: missing.bin")
        != std::string::npos
    );
}

TEST_CASE(
    "File authentication rejects files larger than the maximum allowed size",
    "[file-authentication][validation][size]"
)
{
    FileAuthenticationFixture fixture;
    ScopedTempDirectory temp_directory("file_auth_oversized_file_test");

    const fs::path oversized_file =
        temp_directory.path() / "oversized.bin";

    // resize_file creates the required test size without writing
    // MAX_FILE_SIZE bytes manually.
    {
        std::ofstream file(oversized_file, std::ios::binary);
        REQUIRE(file.is_open());
    }

    fs::resize_file(
        oversized_file,
        static_cast<std::uintmax_t>(MAX_FILE_SIZE) + 1U
    );

    REQUIRE(
        fs::file_size(oversized_file)
        == static_cast<std::uintmax_t>(MAX_FILE_SIZE) + 1U
    );

    REQUIRE_THROWS_AS(
        fixture.get_file_authentication().backup_files(
            temp_directory.path().string(),
            {"oversized.bin"}
        ),
        ClientException
    );
}
