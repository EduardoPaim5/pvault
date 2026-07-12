cmake_minimum_required(VERSION 3.24)

project(
    pvault
    VERSION 0.1.0
    DESCRIPTION "A local-first, keyboard-driven password vault"
    LANGUAGES C
)

include(CTest)
include(GNUInstallDirs)
find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.22)
pkg_check_modules(CBOR REQUIRED IMPORTED_TARGET libcbor>=0.14.0)
pkg_check_modules(NCURSESW REQUIRED IMPORTED_TARGET ncursesw)

option(PVAULT_ENABLE_HARDENING "Enable compiler and linker hardening" ON)
option(PVAULT_ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan" OFF)
option(PVAULT_BUILD_FUZZERS "Build libFuzzer targets" OFF)
option(PVAULT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(PVAULT_BUILD_INTEGRATION_TESTS "Run Linux PTY/process integration tests" ON)
option(
    PVAULT_BUILD_X11_SYSTEM_TESTS
    "Run disposable-X11 system tests with the real xclip"
    OFF
)
if(PVAULT_BUILD_X11_SYSTEM_TESTS AND NOT BUILD_TESTING)
    message(FATAL_ERROR "PVAULT_BUILD_X11_SYSTEM_TESTS requires BUILD_TESTING=ON")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_definitions(_GNU_SOURCE _POSIX_C_SOURCE=200809L)

function(pvault_warnings target)
    target_compile_options(${target} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wformat=2
        -Wundef
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wwrite-strings
        -Wcast-qual
        -Wvla
    )
    if(PVAULT_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE -Werror)
    endif()
endfunction()

set(PVAULT_CORE_SOURCES
    src/arena.c
    src/cbor_codec.c
    src/config.c
    src/crypto.c
    src/error.c
    src/model.c
    src/recovery.c
    src/secure.c
    src/store.c
    src/util.c
)

add_library(pvault_core STATIC ${PVAULT_CORE_SOURCES})

target_include_directories(pvault_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(pvault_core PUBLIC PkgConfig::SODIUM PkgConfig::CBOR)
pvault_warnings(pvault_core)

add_executable(pvault
    src/cli.c
    src/clipboard.c
    src/main.c
    src/shell.c
    src/tty.c
    src/ui.c
)
target_include_directories(pvault PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pvault PRIVATE pvault_core PkgConfig::NCURSESW)
pvault_warnings(pvault)

add_executable(pvault-clip
    src/clip_main.c
    src/clipboard.c
)
target_include_directories(pvault-clip PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pvault-clip PRIVATE pvault_core)
pvault_warnings(pvault-clip)

# Persistence fault injection is compiled into a test-only copy of the core.
# The production binaries always link pvault_core, which has no fault-control
# API or mutable injection state.
if(BUILD_TESTING)
    add_library(pvault_core_test STATIC ${PVAULT_CORE_SOURCES})
    target_include_directories(pvault_core_test
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_link_libraries(pvault_core_test PUBLIC PkgConfig::SODIUM PkgConfig::CBOR)
    target_compile_definitions(pvault_core_test PRIVATE PVAULT_TEST_FAULT_INJECTION)
    pvault_warnings(pvault_core_test)
endif()

if(PVAULT_ENABLE_HARDENING)
    set(pvault_hardened_targets pvault_core pvault pvault-clip)
    if(TARGET pvault_core_test)
        list(APPEND pvault_hardened_targets pvault_core_test)
    endif()
    foreach(target IN LISTS pvault_hardened_targets)
        target_compile_definitions(${target} PRIVATE $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=3>)
        target_compile_options(${target} PRIVATE
            -fstack-protector-strong
            -fPIE
            -fno-delete-null-pointer-checks
            -fno-strict-overflow
        )
    endforeach()
    target_link_options(pvault PRIVATE -Wl,-z,relro,-z,now -pie)
    target_link_options(pvault-clip PRIVATE -Wl,-z,relro,-z,now -pie)
endif()

if(PVAULT_ENABLE_SANITIZERS)
    set(pvault_sanitized_targets pvault_core pvault pvault-clip)
    if(TARGET pvault_core_test)
        list(APPEND pvault_sanitized_targets pvault_core_test)
    endif()
    foreach(target IN LISTS pvault_sanitized_targets)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endforeach()
endif()

if(BUILD_TESTING)
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)

    add_executable(pvault_tests
        tests/test_main.c
        tests/test_cbor.c
        tests/test_compat.c
        tests/test_config.c
        tests/test_crypto.c
        tests/test_recovery.c
        tests/test_rescue.c
        tests/test_backup_retention.c
        tests/test_store.c
        tests/test_store_faults.c
        tests/test_store_security.c
    )
    target_include_directories(pvault_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(pvault_tests PRIVATE pvault_core_test)
    target_compile_definitions(pvault_tests PRIVATE PVAULT_TEST_FAULT_INJECTION)
    pvault_warnings(pvault_tests)
    if(PVAULT_ENABLE_SANITIZERS)
        target_compile_options(pvault_tests PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        )
        target_link_options(pvault_tests PRIVATE -fsanitize=address,undefined)
    endif()
    add_test(NAME pvault_tests COMMAND pvault_tests)
    set_tests_properties(
        pvault_tests
        PROPERTIES
            LABELS unit
            TIMEOUT 180
            ENVIRONMENT
                "PVAULT_V1_VECTOR_PATH=${CMAKE_CURRENT_SOURCE_DIR}/tests/compat/pvault-v1-synthetic.bin"
    )

    add_test(
        NAME pvault_v1_compat_vector
        COMMAND
            ${CMAKE_COMMAND} -E env
            "PYTHONDONTWRITEBYTECODE=1"
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/compat/pvault_v1_vector.py
            --check
    )
    set_tests_properties(
        pvault_v1_compat_vector
        PROPERTIES LABELS "unit;compatibility;format" TIMEOUT 120
    )

    if(PVAULT_BUILD_INTEGRATION_TESTS)
        if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
            message(FATAL_ERROR "PVAULT_BUILD_INTEGRATION_TESTS currently requires Linux")
        endif()
        add_test(
            NAME pvault_integration_tests
            COMMAND
                ${CMAKE_COMMAND} -E env
                "PVAULT_BUILD_DIR=$<TARGET_FILE_DIR:pvault>"
                "CC=${CMAKE_C_COMPILER}"
                ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run.py
        )
        set_tests_properties(
            pvault_integration_tests
            PROPERTIES DEPENDS pvault_tests LABELS integration TIMEOUT 120
        )
        add_test(
            NAME pvault_restore_drill
            COMMAND
                ${CMAKE_COMMAND} -E env
                "PVAULT_BUILD_DIR=$<TARGET_FILE_DIR:pvault>"
                "PYTHONDONTWRITEBYTECODE=1"
                ${CMAKE_CURRENT_SOURCE_DIR}/scripts/restore-drill.sh
        )
        set_tests_properties(
            pvault_restore_drill
            PROPERTIES
                DEPENDS pvault_tests
                LABELS "integration;recovery;restore-drill"
                TIMEOUT 90
        )
    endif()

    if(PVAULT_BUILD_X11_SYSTEM_TESTS)
        if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
            message(FATAL_ERROR "PVAULT_BUILD_X11_SYSTEM_TESTS currently requires Linux")
        endif()
        if(NOT EXISTS "/usr/bin/xclip")
            message(FATAL_ERROR "PVAULT_BUILD_X11_SYSTEM_TESTS requires /usr/bin/xclip")
        endif()
        find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
        find_program(PVAULT_XVFB_EXECUTABLE NAMES Xvfb REQUIRED)
        pkg_check_modules(X11 REQUIRED IMPORTED_TARGET x11)

        add_executable(
            pvault_x11_clipboard_driver
            tests/integration/clipboard_driver.c
            src/clipboard.c
        )
        target_include_directories(
            pvault_x11_clipboard_driver
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        target_link_libraries(pvault_x11_clipboard_driver PRIVATE pvault_core)
        pvault_warnings(pvault_x11_clipboard_driver)

        add_executable(
            pvault_x11_selection_owner
            tests/system/x11_selection_owner.c
        )
        target_link_libraries(pvault_x11_selection_owner PRIVATE PkgConfig::X11)
        pvault_warnings(pvault_x11_selection_owner)

        if(PVAULT_ENABLE_HARDENING)
            foreach(target pvault_x11_clipboard_driver pvault_x11_selection_owner)
                target_compile_definitions(
                    ${target}
                    PRIVATE $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=3>
                )
                target_compile_options(${target} PRIVATE
                    -fstack-protector-strong
                    -fPIE
                    -fno-delete-null-pointer-checks
                    -fno-strict-overflow
                )
                target_link_options(${target} PRIVATE -Wl,-z,relro,-z,now -pie)
            endforeach()
        endif()
        if(PVAULT_ENABLE_SANITIZERS)
            foreach(target pvault_x11_clipboard_driver pvault_x11_selection_owner)
                target_compile_options(${target} PRIVATE
                    -fsanitize=address,undefined
                    -fno-omit-frame-pointer
                )
                target_link_options(${target} PRIVATE -fsanitize=address,undefined)
            endforeach()
        endif()

        add_test(
            NAME pvault_x11_system_tests
            COMMAND
                ${CMAKE_COMMAND} -E env
                "PVAULT_X11_DRIVER=$<TARGET_FILE:pvault_x11_clipboard_driver>"
                "PVAULT_X11_OWNER_QUERY=$<TARGET_FILE:pvault_x11_selection_owner>"
                "PVAULT_XVFB=${PVAULT_XVFB_EXECUTABLE}"
                ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/system/test_xclip_x11.py
        )
        set_tests_properties(
            pvault_x11_system_tests
            PROPERTIES LABELS "system;real-clipboard;x11" TIMEOUT 45
        )
    endif()
endif()

if(PVAULT_BUILD_FUZZERS)
    add_library(pvault_core_fuzz STATIC ${PVAULT_CORE_SOURCES})
    target_include_directories(pvault_core_fuzz
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_link_libraries(pvault_core_fuzz PUBLIC PkgConfig::SODIUM PkgConfig::CBOR)
    target_compile_options(pvault_core_fuzz PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined
        -fno-omit-frame-pointer
    )
    pvault_warnings(pvault_core_fuzz)

    foreach(fuzzer fuzz_header fuzz_cbor fuzz_recovery)
        add_executable(${fuzzer} fuzz/${fuzzer}.c)
        target_include_directories(${fuzzer} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(${fuzzer} PRIVATE pvault_core_fuzz)
        target_compile_options(${fuzzer} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fno-omit-frame-pointer
        )
        target_link_options(${fuzzer} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()

install(TARGETS pvault pvault-clip RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES docs/pvault.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 OPTIONAL)
install(FILES LICENSE COPYRIGHT DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/licenses/pvault)
install(FILES
    README.md
    SECURITY.md
    THREAT_MODEL.md
    CONTRIBUTING.md
    docs/FORMAT.md
    docs/COMPATIBILITY.md
    docs/ARCHITECTURE.pt-BR.md
    docs/ROADMAP.pt-BR.md
    docs/RELEASES.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)
