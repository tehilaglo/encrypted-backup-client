# Encrypted Backup Client

## Overview

This repository contains a C++ client for an encrypted backup workflow.

- Connects to a remote server over TCP.
- Performs registration or re-registration.
- Encrypts/authenticates files before transfer.
- Lets the user select files from a chosen directory for backup.

Main application entry point: `src/main.cpp` (build target: `client`).

## Stack

- **Language:** C++17
- **Build system:** CMake (`cmake_minimum_required(VERSION 3.16)`)
- **Primary libraries/frameworks:**
  - Boost (`system`, `thread`, `stacktrace_basic`, and JSON usage in code)
  - Crypto++
- **Package manager:**
  - No repository-level package manager is configured.
  - Dependencies are discovered via CMake (`find_package` / `find_library`).
  - TODO: Document the team-preferred dependency installation method per OS.

## Requirements

- CMake `>= 3.16`
- C++17-compatible compiler (Clang/GCC)
- Boost `>= 1.75` with components:
  - `system`
  - `thread`
  - `stacktrace_basic`
- Crypto++ development headers and library

> Note: `CMakeLists.txt` searches common macOS/Homebrew and `/usr/local` paths for Crypto++.

## Project Setup

From the `client/` directory:

```bash
cmake -S . -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-debug --target client
```

The executable output is configured to the project root as `./client`.

## Run

Run from the `client/` directory after building:

```bash
./client
```

At runtime, the app expects:

- `../server_config.json` (relative to current working directory)
- and will create/use local files in the working directory, including:
  - `me.info`
  - `name.info`
  - `transfer.info`
  - `private.key`
  - `aes.key` (temporary; removed on exit)
  - `client.log`

Expected server config shape:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 12345
  }
}
```

## Scripts

- `cleanup.sh`
  - Removes `me.info`, `private.key`, and `client.log` under `client/`.

  ```bash
  ./cleanup.sh
  ```

- `demo/run_demo.sh`
  - Creates demo input (`demo/user_input_demo.txt`) and runs `./client` with redirected input.

  ```bash
  ./demo/run_demo.sh
  ```

## Environment Variables

No runtime environment variables were detected in the current codebase (`getenv` usage not found).

If you add env-based configuration later, document it here in this format:

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `TODO_ENV_VAR` | yes/no | `TODO` | TODO |

## Tests

- No CMake/CTest test targets are currently defined (`add_test` not found).
- The `stubs/` folder appears to contain standalone/support sources, but no automated test harness is configured.

TODO:
- Define and document the official test strategy and commands (unit/integration/manual).

## Project Structure

```text
client/
├── CMakeLists.txt
├── cleanup.sh
├── demo/
│   ├── demo_files/
│   ├── run_demo.sh
│   └── user_input_demo.txt
├── include/
│   ├── config/
│   ├── core/
│   ├── crypto/
│   ├── protocol/
│   ├── registration/
│   ├── ui/
│   └── utils/
├── src/
│   ├── config/
│   ├── core/
│   ├── crypto/
│   ├── protocol/
│   ├── registration/
│   ├── ui/
│   ├── utils/
│   └── main.cpp
└── stubs/
```

## License

TODO: Add license information. No license file was found in this repository snapshot.