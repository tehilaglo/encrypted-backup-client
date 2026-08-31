include(FetchContent)

find_package(Catch2 3 QUIET)

if(NOT Catch2_FOUND)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.6.0
    )
    FetchContent_MakeAvailable(Catch2)
endif()

add_executable(protocol_tests
    test_file_authentication.cpp
    test_request_serialization.cpp
    test_response_deserialization.cpp
    test_response_malformed.cpp
    test_protocol_fields.cpp
    test_encoding_utils.cpp
    test_protocol_codes.cpp

    ../src/protocol/request.cpp
    ../src/protocol/response.cpp
    ../src/utils/encoding_utils.cpp
)

target_include_directories(protocol_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    ${CRYPTOPP_INCLUDE_DIR}
)

target_compile_options(protocol_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(protocol_tests PRIVATE
    Catch2::Catch2WithMain
    ${CRYPTOPP_LIBRARY}
    ${CMAKE_DL_LIBS}
)

add_test(NAME protocol_tests COMMAND protocol_tests)
