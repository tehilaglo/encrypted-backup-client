# Encrypted Backup Client

A C++17 command-line backup client that communicates with a remote server over TCP, performs RSA-based key exchange, encrypts files with AES, and transfers them using a custom binary protocol.

> **Project scope:** This repository contains the **client application only**. A compatible backup server implementing the same protocol must be running before registration or file uploads can succeed.

## What This Project Demonstrates

This project was built to practice and demonstrate:

* client-server communication over TCP;
* binary protocol design and serialization;
* modular C++ application architecture;
* RSA and AES cryptographic workflows;
* chunked file transfer;
* integrity verification and retry handling;
* persistent client identity and re-registration;
* automated testing with Catch2 and CTest.

## Features

* TCP communication using Boost.Asio
* New-client registration and existing-client re-registration
* RSA public-key exchange
* AES key delivery encrypted with the client's RSA public key
* AES encryption of files before transmission
* Chunked encrypted file uploads
* CRC32-based file integrity verification
* Retry handling when CRC verification fails
* Binary request serialization and response deserialization
* Validation of malformed protocol responses
* Interactive directory and file selection
* Local persistence of client identity and key material
* Catch2 test suite integrated with CTest

## How It Works

A typical backup session follows this flow:

1. The client reads the server address from `server_config.json`.
2. It establishes a TCP connection with the configured server.
3. If no local client identity exists, the client performs registration.
4. Otherwise, it attempts re-registration using its stored credentials.
5. During key exchange:

  * the client generates an RSA key pair;
  * the public key is sent to the server;
  * the server returns an AES key encrypted with that RSA public key;
  * the client decrypts and stores the AES key locally for the session.
6. The user selects a directory and files to back up.
7. Each selected file is:

  * validated;
  * encrypted using AES;
  * split into protocol chunks;
  * transmitted to the server.
8. The server returns file metadata and a CRC checksum.
9. The client compares the returned information with its local data and reports success or retries the transfer when necessary.
10. The client disconnects and removes its temporary AES key during normal shutdown.

## Architecture

The source is organized by responsibility:

| Module         | Responsibility                                                                       |
| -------------- | ------------------------------------------------------------------------------------ |
| `config`       | Runtime paths and server configuration                                               |
| `core`         | Main application workflow and TCP communication                                      |
| `crypto`       | AES/RSA operations and encrypted file-transfer logic                                 |
| `protocol`     | Protocol types, operation codes, request serialization, and response deserialization |
| `registration` | Registration, re-registration, credential management, and key exchange               |
| `ui`           | Console interaction and backup selection                                             |
| `utils`        | Input validation, encoding, logging, and supporting utilities                        |

At the center of the application, `ClientHandler` coordinates connection, registration, backup, and disconnection. `CommunicationManager` provides the transport layer, while the protocol classes convert between C++ objects and the binary representation sent over the network.

## Technology

* **Language:** C++17
* **Build system:** CMake 3.16+
* **Networking:** Boost.Asio
* **Supporting Boost components:** System, Thread, Stacktrace
* **Cryptography:** Crypto++
* **Testing:** Catch2 v3 and CTest

## Supported Environment

The documented build and demo workflow currently targets Unix-like development environments such as **macOS and Linux**.

Windows/MSVC support has not been verified.

## Prerequisites

Before building the project, install:

* a C++17-compatible compiler;
* CMake 3.16 or newer;
* Boost 1.75 or newer with:

  * `system`
  * `thread`
  * `stacktrace_basic`;
* Crypto++ development headers and library;
* Git, if Catch2 needs to be retrieved automatically while configuring the tests.

### Crypto++ Location

CMake searches common Homebrew and `/usr/local` installation locations automatically.

For a custom Crypto++ installation:

```bash
cmake -S . -B build \
  -DCRYPTOPP_INCLUDE_DIR=/path/to/include \
  -DCRYPTOPP_LIBRARY=/path/to/libcryptopp
```

## Build

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target client
```

On macOS, no additional architecture flag is normally required. CMake detects the native architecture before enabling the compiler, including Apple Silicon hosts when CMake is launched from a Rosetta-translated terminal. An explicitly supplied `-DCMAKE_OSX_ARCHITECTURES=...` value is still respected for intentional cross-architecture builds.

The current CMake configuration places the generated executable in the repository root.

Run it with:

```bash
./client
```

For a debug build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target client
```

## Configuration

Edit `server_config.json` before running the client:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 1234
  }
}
```

The host and port must match the compatible server instance.

`server_config.json` is resolved relative to the client's **current working directory**, so the standard workflow is to run `./client` from the repository root.

## Run

Start the compatible backup server first.

Then, from the repository root:

```bash
./client
```

The application will guide you through:

1. registration or re-registration;
2. backup-directory selection;
3. file selection;
4. encrypted file upload.

## Tests

The current automated test suite covers:

* protocol constants and operation codes;
* request serialization;
* response deserialization;
* malformed and incomplete responses;
* encoding utilities;
* pre-upload file validation.

Configure the project with testing enabled:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON
```

Build the test executable:

```bash
cmake --build build --target protocol_tests
```

Run the suite through CTest:

```bash
ctest --test-dir build --output-on-failure
```

The test configuration first looks for an installed **Catch2 v3** package. If one is not available, CMake retrieves the pinned **Catch2 v3.6.0** release using `FetchContent`.

## Demo

A scripted terminal demonstration is available under `demo/`.

Run it from the repository root:

```bash
./demo/run_demo.sh
```

The demo script automatically:

1. configures a Release build under `build/demo/`;
2. builds the `client` executable with testing disabled;
3. creates the temporary scripted input used by the demonstration;
4. generates a 21 MiB test file at runtime to exercise the client's 20 MiB file-size limit without storing a large binary asset in the repository;
5. launches the client against the files under `demo/demo_files/`;
6. removes temporary demo-generated files when the script exits.

On macOS, the top-level CMake configuration selects the native build architecture before enabling the compiler. On Apple Silicon, this keeps normal builds and the demo aligned with native arm64 Homebrew dependencies even when CMake is launched from a Rosetta-translated terminal.

A compatible backup server must already be running at the address specified in `server_config.json`.

The demo exercises behavior such as:

* username validation;
* directory and file selection;
* invalid filename handling;
* oversized-file rejection;
* multiple encrypted file uploads.

The generated `client` executable and `build/demo/` directory are build artifacts and may be removed manually when no longer needed.


## Project Structure

```text
.
├── include/              Public headers organized by module
├── src/                  Client implementation
├── tests/                Catch2 automated tests
├── demo/                 Scripted demonstration and sample files
├── CMakeLists.txt        Main CMake build configuration
├── server_config.json    Server connection configuration
├── cleanup.sh            Removes selected generated client state
└── LICENSE               MIT license
```

## Runtime Files

During normal operation, the client may create local state and key files, including:

* `me.info` — client identity and registration information;
* `private.key` — locally stored RSA private key;
* `aes.key` — temporary AES key used during the active client session;
* `client.log` — application diagnostic log.

Additional runtime filenames are defined by the client configuration for supporting workflows.

The AES key is removed during normal application shutdown. An abnormal termination may leave the file behind.

These files should **never be committed to Git**.

## Cleanup

The provided cleanup script can remove selected generated files:

```bash
./cleanup.sh
```

Currently, it removes:

* `me.info`
* `private.key`
* `client.log`

It is not intended to guarantee removal of every possible generated runtime file.

## Security Notice

This project is an educational and portfolio implementation and has **not been independently security-audited**.

It should not be used to protect production or sensitive data without a thorough security review.

In particular:

* CRC32 is used for transfer-integrity verification and is **not** a cryptographic authentication mechanism.
* Local key material is stored in files rather than a protected operating-system key store.
* Base64 encoding of key material is an encoding format, **not encryption**.
* The custom network protocol and its cryptographic design should undergo a dedicated threat-model and security review before production use.

## License

Distributed under the [MIT License](LICENSE).
