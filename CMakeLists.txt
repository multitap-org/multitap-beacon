# beacon: introduction server for piccolo's remote play over the internet,
# and the wire library its clients share (PROTOCOL.md).
#
#   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DMULTITAP_WARNINGS_AS_ERRORS=ON
#   cmake --build build && ctest --test-dir build
#
# Used as a subproject (frontends-common), only the `beacon_wire` library
# is built unless BEACON_SERVER / BEACON_TESTS are turned on.

cmake_minimum_required(VERSION 3.25)
project(beacon VERSION 1.0.0 LANGUAGES C CXX)

option(MULTITAP_WARNINGS_AS_ERRORS "Warnings in our code are errors" OFF)
option(MULTITAP_SANITIZE "Build our code with ASan + UBSan" OFF)
option(BEACON_SERVER "Build the server (Linux)" ${PROJECT_IS_TOP_LEVEL})
option(BEACON_TESTS "Build the tests" ${PROJECT_IS_TOP_LEVEL})
option(BEACON_FUZZ "Build the libFuzzer target (Clang only)" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Flags for OUR code only (the same set as multitap's multitap_set_project_flags).
function(beacon_set_flags target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
        if(MULTITAP_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic
            -Wconversion -Wsign-conversion -Wshadow
            -Wold-style-cast -Wcast-qual -Wnull-dereference
            # Designated initializers leave unnamed fields zeroed on purpose.
            -Wno-missing-field-initializers
            -fno-exceptions -fno-rtti)
        if(MULTITAP_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
        if(MULTITAP_SANITIZE)
            target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()

# --- The wire library: no dependencies, shared with the clients -------------
add_library(beacon_wire STATIC wire/beacon_wire.cpp)
target_include_directories(beacon_wire PUBLIC wire)
beacon_set_flags(beacon_wire)

if(NOT BEACON_SERVER AND NOT BEACON_TESTS)
    return()
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "the beacon server is Linux only for now (the wire library builds anywhere)")
endif()

# --- Monocypher (deps/monocypher, BSD-2-Clause or CC0): keyed BLAKE2b -------
set(BEACON_MONOCYPHER "${CMAKE_CURRENT_SOURCE_DIR}/deps/monocypher")
if(NOT EXISTS "${BEACON_MONOCYPHER}/src/monocypher.c")
    message(FATAL_ERROR "deps/monocypher is missing: git submodule update --init")
endif()
add_library(beacon_dep_monocypher STATIC "${BEACON_MONOCYPHER}/src/monocypher.c")
target_include_directories(beacon_dep_monocypher SYSTEM PUBLIC "${BEACON_MONOCYPHER}/src")
set_target_properties(beacon_dep_monocypher PROPERTIES C_STANDARD 99 POSITION_INDEPENDENT_CODE ON)
if(NOT MSVC)
    target_compile_options(beacon_dep_monocypher PRIVATE -O2)
endif()

# --- The server, as a library (the tests use it) plus main.cpp --------------
add_library(beacon_core STATIC
    server/beacon_log.cpp
    server/beacon_random.cpp
    server/beacon_server.cpp
    server/beacon_net.cpp
    server/beacon_status.cpp
    server/beacon_stun.cpp
    server/beacon_ws.cpp
    server/beacon_signal.cpp)
target_include_directories(beacon_core PUBLIC server)
target_link_libraries(beacon_core PUBLIC beacon_wire PRIVATE beacon_dep_monocypher)
beacon_set_flags(beacon_core)

if(BEACON_SERVER)
    add_executable(beacon server/main.cpp)
    target_link_libraries(beacon PRIVATE beacon_core)
    target_compile_definitions(beacon PRIVATE BEACON_VERSION_STRING="${PROJECT_VERSION}")
    beacon_set_flags(beacon)
    include(GNUInstallDirs)
    install(TARGETS beacon RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BEACON_TESTS)
    enable_testing()

    add_executable(beacon_wire_test tests/wire_test.cpp)
    target_link_libraries(beacon_wire_test PRIVATE beacon_wire)
    beacon_set_flags(beacon_wire_test)
    add_test(NAME wire COMMAND beacon_wire_test)

    add_executable(beacon_server_test tests/server_test.cpp)
    target_link_libraries(beacon_server_test PRIVATE beacon_core)
    beacon_set_flags(beacon_server_test)
    add_test(NAME server COMMAND beacon_server_test)

    add_executable(beacon_stun_test tests/stun_test.cpp)
    target_link_libraries(beacon_stun_test PRIVATE beacon_core)
    beacon_set_flags(beacon_stun_test)
    add_test(NAME stun COMMAND beacon_stun_test)

    add_executable(beacon_ws_test tests/ws_test.cpp)
    target_link_libraries(beacon_ws_test PRIVATE beacon_core)
    beacon_set_flags(beacon_ws_test)
    add_test(NAME ws COMMAND beacon_ws_test)

    add_executable(beacon_signal_test tests/signal_test.cpp)
    target_link_libraries(beacon_signal_test PRIVATE beacon_core)
    beacon_set_flags(beacon_signal_test)
    add_test(NAME signal COMMAND beacon_signal_test)

    add_executable(beacon_loopback_test tests/loopback_test.cpp)
    target_link_libraries(beacon_loopback_test PRIVATE beacon_core)
    beacon_set_flags(beacon_loopback_test)
    add_test(NAME loopback COMMAND beacon_loopback_test)

    # The fuzz entry point driven by a plain main(): every mutation of every
    # valid message plus random packets, so any compiler runs it in ctest.
    add_executable(beacon_fuzz_replay tests/fuzz_replay.cpp tests/fuzz_wire.cpp)
    target_link_libraries(beacon_fuzz_replay PRIVATE beacon_wire)
    beacon_set_flags(beacon_fuzz_replay)
    add_test(NAME fuzz_replay COMMAND beacon_fuzz_replay)

    add_executable(beacon_fuzz_stun_replay tests/fuzz_stun_replay.cpp tests/fuzz_stun.cpp)
    target_link_libraries(beacon_fuzz_stun_replay PRIVATE beacon_core)
    beacon_set_flags(beacon_fuzz_stun_replay)
    add_test(NAME fuzz_stun_replay COMMAND beacon_fuzz_stun_replay)

    add_executable(beacon_fuzz_ws_handshake_replay tests/fuzz_ws_replay.cpp tests/fuzz_ws_handshake.cpp)
    target_link_libraries(beacon_fuzz_ws_handshake_replay PRIVATE beacon_core)
    beacon_set_flags(beacon_fuzz_ws_handshake_replay)
    add_test(NAME fuzz_ws_handshake_replay COMMAND beacon_fuzz_ws_handshake_replay handshake)

    add_executable(beacon_fuzz_ws_frame_replay tests/fuzz_ws_replay.cpp tests/fuzz_ws_frame.cpp)
    target_link_libraries(beacon_fuzz_ws_frame_replay PRIVATE beacon_core)
    beacon_set_flags(beacon_fuzz_ws_frame_replay)
    add_test(NAME fuzz_ws_frame_replay COMMAND beacon_fuzz_ws_frame_replay frame)

    # The real libFuzzer target, with Clang and its runtime (Debian/Ubuntu:
    # libclang-rt-<version>-dev).
    set(BEACON_HAVE_LIBFUZZER OFF)
    if(BEACON_FUZZ AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        include(CheckCXXSourceCompiles)
        set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer,address,undefined")
        set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=fuzzer,address,undefined")
        check_cxx_source_compiles(
            "#include <cstddef>\n#include <cstdint>\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }"
            BEACON_LIBFUZZER_LINKS)
        unset(CMAKE_REQUIRED_FLAGS)
        unset(CMAKE_REQUIRED_LINK_OPTIONS)
        if(BEACON_LIBFUZZER_LINKS)
            set(BEACON_HAVE_LIBFUZZER ON)
        else()
            message(STATUS "beacon: Clang without the libFuzzer/sanitizer runtime: no libFuzzer targets")
        endif()
    endif()
    if(BEACON_HAVE_LIBFUZZER)
        add_executable(beacon_fuzz_wire tests/fuzz_wire.cpp wire/beacon_wire.cpp)
        target_include_directories(beacon_fuzz_wire PRIVATE wire)
        beacon_set_flags(beacon_fuzz_wire)
        target_compile_options(beacon_fuzz_wire PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(beacon_fuzz_wire PRIVATE -fsanitize=fuzzer,address,undefined)
        add_test(NAME fuzz_wire COMMAND beacon_fuzz_wire -runs=2000000 -seed=1)

        add_executable(beacon_fuzz_stun tests/fuzz_stun.cpp server/beacon_stun.cpp wire/beacon_wire.cpp)
        target_include_directories(beacon_fuzz_stun PRIVATE wire server)
        beacon_set_flags(beacon_fuzz_stun)
        target_compile_options(beacon_fuzz_stun PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(beacon_fuzz_stun PRIVATE -fsanitize=fuzzer,address,undefined)
        add_test(NAME fuzz_stun COMMAND beacon_fuzz_stun -runs=2000000 -seed=1)

        add_executable(beacon_fuzz_ws_handshake tests/fuzz_ws_handshake.cpp server/beacon_ws.cpp wire/beacon_wire.cpp)
        target_include_directories(beacon_fuzz_ws_handshake PRIVATE wire server)
        beacon_set_flags(beacon_fuzz_ws_handshake)
        target_compile_options(beacon_fuzz_ws_handshake PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(beacon_fuzz_ws_handshake PRIVATE -fsanitize=fuzzer,address,undefined)
        add_test(NAME fuzz_ws_handshake COMMAND beacon_fuzz_ws_handshake -runs=1000000 -seed=1)

        add_executable(beacon_fuzz_ws_frame tests/fuzz_ws_frame.cpp server/beacon_ws.cpp wire/beacon_wire.cpp)
        target_include_directories(beacon_fuzz_ws_frame PRIVATE wire server)
        beacon_set_flags(beacon_fuzz_ws_frame)
        target_compile_options(beacon_fuzz_ws_frame PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(beacon_fuzz_ws_frame PRIVATE -fsanitize=fuzzer,address,undefined)
        add_test(NAME fuzz_ws_frame COMMAND beacon_fuzz_ws_frame -runs=2000000 -seed=1)
    endif()
endif()

# Benchmark (not a test): beacon_bench logic | blast PORT SECONDS
if(BEACON_TESTS)
    add_executable(beacon_bench tools/beacon_bench.cpp)
    target_link_libraries(beacon_bench PRIVATE beacon_core)
    beacon_set_flags(beacon_bench)
endif()
