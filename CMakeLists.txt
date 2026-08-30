cmake_minimum_required(VERSION 3.16)

# Project name. VERSION is optional, so omitted here for simplicity.
project(client LANGUAGES CXX)

include(CTest)

# --------------------------------------------------
# C++ standard
# --------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Use Debug by default if no build type was provided.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# --------------------------------------------------
# Dependencies
# --------------------------------------------------
find_package(Boost 1.75 REQUIRED COMPONENTS system thread stacktrace_basic)

# Try common install locations for Crypto++
find_path(CRYPTOPP_INCLUDE_DIR
        NAMES cryptopp/aes.h
        HINTS
        /opt/homebrew/include
        /usr/local/include
)

find_library(CRYPTOPP_LIBRARY
        NAMES cryptopp
        HINTS
        /opt/homebrew/lib
        /usr/local/lib
)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ not found. Install it or set CRYPTOPP_INCLUDE_DIR / CRYPTOPP_LIBRARY manually.")
endif()

# --------------------------------------------------
# Source files
# --------------------------------------------------
# Recursively collect all .cpp files under src/
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

if(NOT SOURCES)
    message(FATAL_ERROR "No source files found under ${CMAKE_CURRENT_SOURCE_DIR}/src")
endif()

# Build the client executable
add_executable(client ${SOURCES})

# --------------------------------------------------
# Include directories
# --------------------------------------------------
target_include_directories(client PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        ${CRYPTOPP_INCLUDE_DIR}
)

# --------------------------------------------------
# Compiler options
# --------------------------------------------------
target_compile_options(client PRIVATE
        $<$<CONFIG:Debug>:-g -O0>
        $<$<CONFIG:Release>:-O2>
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
)

# Needed for Boost stacktrace on some platforms/configurations
target_compile_definitions(client PRIVATE
        BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
)

# --------------------------------------------------
# Link libraries
# --------------------------------------------------
target_link_libraries(client PRIVATE
        Boost::system
        Boost::thread
        Boost::stacktrace_basic
        ${CRYPTOPP_LIBRARY}
        ${CMAKE_DL_LIBS}
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# --------------------------------------------------
# Optional IDE grouping
# --------------------------------------------------
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/src" FILES ${SOURCES})

# Helpful configure-time output
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Crypto++ include dir: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library: ${CRYPTOPP_LIBRARY}")
