# ==============================================================================
# Encrypted Backup Client - Build Configuration
#
# Configures the main C++ client application, reusable client_core library,
# third-party dependencies, compiler settings, and optional test targets.
#
# Dependencies:
#   - Boost 1.75+
#   - Crypto++
#   - Catch2 (through the tests subdirectory when BUILD_TESTING is enabled)
#
# @author Tehila Cahnaman
# ==============================================================================

cmake_minimum_required(VERSION 3.16)

project(client LANGUAGES CXX)

include(CTest)


# ------------------------------------------------------------------------------
# C++ configuration
# ------------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to a Debug build when no explicit build type is supplied.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# Place generated executables in the project root directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})


# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

find_package(Boost 1.75 REQUIRED COMPONENTS system thread stacktrace_basic)

# Locate Crypto++ in common Homebrew and local installation directories.
find_path(
        CRYPTOPP_INCLUDE_DIR
        NAMES cryptopp/aes.h
        HINTS
        /opt/homebrew/include
        /usr/local/include
)

find_library(
        CRYPTOPP_LIBRARY
        NAMES cryptopp
        HINTS
        /opt/homebrew/lib
        /usr/local/lib
)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(
            FATAL_ERROR
            "Crypto++ not found. Install it or set CRYPTOPP_INCLUDE_DIR / CRYPTOPP_LIBRARY manually."
    )
endif()


# ------------------------------------------------------------------------------
# Application sources
# ------------------------------------------------------------------------------

# Collect implementation files recursively from src/.
file(
        GLOB_RECURSE SOURCES
        CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

if(NOT SOURCES)
    message(
            FATAL_ERROR
            "No source files found under ${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
endif()

# main.cpp belongs exclusively to the client executable and is excluded from
# the reusable client_core library.
set(CLIENT_MAIN "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
list(REMOVE_ITEM SOURCES "${CLIENT_MAIN}")


# ------------------------------------------------------------------------------
# Client core library
# ------------------------------------------------------------------------------

# Build application logic separately so it can also be linked by test targets.
add_library(
        client_core STATIC
        ${SOURCES}
)

target_include_directories(
        client_core PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        ${CRYPTOPP_INCLUDE_DIR}
)

target_compile_options(
        client_core PRIVATE
        $<$<CONFIG:Debug>:-g -O0>
        $<$<CONFIG:Release>:-O2>
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
)

# Required by the selected Boost.Stacktrace configuration on supported systems.
target_compile_definitions(
        client_core PUBLIC
        BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
)

target_link_libraries(
        client_core PUBLIC
        Boost::system
        Boost::thread
        Boost::stacktrace_basic
        ${CRYPTOPP_LIBRARY}
        ${CMAKE_DL_LIBS}
)


# ------------------------------------------------------------------------------
# Client executable
# ------------------------------------------------------------------------------

add_executable(
        client
        ${CLIENT_MAIN}
)

target_link_libraries(
        client PRIVATE
        client_core
)


# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

# Test targets are configured separately under tests/.
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()


# ------------------------------------------------------------------------------
# IDE organization
# ------------------------------------------------------------------------------

# Preserve the src/ directory hierarchy when sources are displayed by supported
# IDEs and project generators.
source_group(
        TREE "${CMAKE_CURRENT_SOURCE_DIR}/src"
        FILES ${SOURCES}
)


# ------------------------------------------------------------------------------
# Configuration summary
# ------------------------------------------------------------------------------

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Crypto++ include dir: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library: ${CRYPTOPP_LIBRARY}")
