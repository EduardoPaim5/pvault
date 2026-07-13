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
option(PVAULT_ENABLE_LSAN "Enable the standalone LeakSanitizer test profile" OFF)
option(PVAULT_BUILD_FUZZERS "Build libFuzzer targets" OFF)
option(PVAULT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(PVAULT_BUILD_INTEGRATION_TESTS "Run Linux PTY/process integration tests" ON)
option(
    PVAULT_BUILD_X11_SYSTEM_TESTS
    "Run disposable-X11 system tests with the real xclip"
    OFF
)
option(
    PVAULT_BUILD_LIVE_X11_CANARY
    "Build the manual, never-CI live i3/X11 clipboard canary"
    OFF
)
option(
    PVAULT_BUILD_WAYLAND_SYSTEM_TESTS
    "Characterize the non-installable experimental wl-copy backend on disposable Wayland"
    OFF
)
if(PVAULT_BUILD_X11_SYSTEM_TESTS AND NOT BUILD_TESTING)
    message(FATAL_ERROR "PVAULT_BUILD_X11_SYSTEM_TESTS requires BUILD_TESTING=ON")
endif()
if(PVAULT_BUILD_LIVE_X11_CANARY AND NOT BUILD_TESTING)
    message(FATAL_ERROR "PVAULT_BUILD_LIVE_X11_CANARY requires BUILD_TESTING=ON")
endif()
if(PVAULT_BUILD_WAYLAND_SYSTEM_TESTS AND NOT BUILD_TESTING)
    message(FATAL_ERROR "PVAULT_BUILD_WAYLAND_SYSTEM_TESTS requires BUILD_TESTING=ON")
endif()
if(PVAULT_ENABLE_LSAN AND NOT BUILD_TESTING)
    message(FATAL_ERROR "PVAULT_ENABLE_LSAN is a test-only profile and requires BUILD_TESTING=ON")
endif()
if(PVAULT_ENABLE_LSAN AND PVAULT_ENABLE_SANITIZERS)
    message(FATAL_ERROR "PVAULT_ENABLE_LSAN cannot be combined with PVAULT_ENABLE_SANITIZERS")
endif()
if(PVAULT_ENABLE_LSAN AND PVAULT_BUILD_FUZZERS)
    message(FATAL_ERROR "PVAULT_ENABLE_LSAN cannot be combined with PVAULT_BUILD_FUZZERS")
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
target_compile_definitions(pvault PRIVATE PVAULT_INSTALLABLE_CLIPBOARD)
pvault_warnings(pvault)

add_executable(pvault-clip
    src/clip_main.c
    src/clipboard.c
)
target_include_directories(pvault-clip PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pvault-clip PRIVATE pvault_core)
target_compile_definitions(pvault-clip PRIVATE PVAULT_INSTALLABLE_CLIPBOARD)
pvault_warnings(pvault-clip)

if(BUILD_TESTING AND PVAULT_BUILD_INTEGRATION_TESTS)
    add_executable(pvault_fake_rofi tests/integration/fake_rofi.c)
    add_executable(
        pvault_fake_clipboard_owner
        tests/integration/fake_clipboard_owner.c
    )
    target_link_libraries(pvault_fake_clipboard_owner PRIVATE PkgConfig::SODIUM)
    add_executable(pvault_signal_launcher tests/integration/signal_launcher.c)
    add_executable(pvault_rofi_test
        src/cli.c
        src/clipboard.c
        src/main.c
        src/shell.c
        src/tty.c
        src/ui.c
    )
    target_include_directories(pvault_rofi_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(pvault_rofi_test PRIVATE pvault_core PkgConfig::NCURSESW)
    target_compile_definitions(
        pvault_rofi_test
        PRIVATE
            PVAULT_EXPERIMENTAL_WAYLAND_CLIPBOARD
            "PVAULT_ROFI_EXECUTABLE=\"$<TARGET_FILE:pvault_fake_rofi>\""
            "PV_XCLIP_PATH=\"$<TARGET_FILE:pvault_fake_clipboard_owner>\""
            "PV_WL_COPY_PATH=\"$<TARGET_FILE:pvault_fake_clipboard_owner>\""
    )
    add_dependencies(
        pvault_rofi_test
        pvault_fake_rofi
        pvault_fake_clipboard_owner
        pvault_signal_launcher
    )
    add_executable(
        pvault_clip_test
        src/clip_main.c
        src/clipboard.c
    )
    target_include_directories(pvault_clip_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(pvault_clip_test PRIVATE pvault_core)
    target_compile_definitions(
        pvault_clip_test
        PRIVATE
            PVAULT_EXPERIMENTAL_WAYLAND_CLIPBOARD
            "PV_XCLIP_PATH=\"$<TARGET_FILE:pvault_fake_clipboard_owner>\""
            "PV_WL_COPY_PATH=\"$<TARGET_FILE:pvault_fake_clipboard_owner>\""
    )
    add_dependencies(pvault_clip_test pvault_fake_clipboard_owner)
    add_executable(
        pvault_clipboard_test_driver
        tests/integration/clipboard_driver.c
        src/clipboard.c
    )
    target_include_directories(
        pvault_clipboard_test_driver
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_link_libraries(pvault_clipboard_test_driver PRIVATE pvault_core)
    target_compile_definitions(
        pvault_clipboard_test_driver
        PRIVATE
            PVAULT_EXPERIMENTAL_WAYLAND_CLIPBOARD
            "PV_XCLIP_PATH=\"$<TARGET_FILE:pvault_fake_clipboard_owner>\""
            "PV_WL_COPY_PATH=\"$<TARGET_FILE:pvault_fake_clipboard_owner>\""
    )
    add_dependencies(
        pvault_clipboard_test_driver
        pvault_fake_clipboard_owner
        pvault_clip_test
    )
    set(pvault_private_test_directory "${CMAKE_CURRENT_BINARY_DIR}/private-cli-test")
    set_target_properties(
        pvault_rofi_test
        PROPERTIES
            OUTPUT_NAME pvault
            RUNTIME_OUTPUT_DIRECTORY "${pvault_private_test_directory}"
    )
    set_target_properties(
        pvault_clip_test
        PROPERTIES
            OUTPUT_NAME pvault-clip
            RUNTIME_OUTPUT_DIRECTORY "${pvault_private_test_directory}"
    )
    set_target_properties(
        pvault_clipboard_test_driver
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${pvault_private_test_directory}"
    )
    set(pvault_rofi_test_targets
        pvault_fake_rofi
        pvault_fake_clipboard_owner
        pvault_signal_launcher
        pvault_rofi_test
        pvault_clip_test
        pvault_clipboard_test_driver
    )
    foreach(target IN LISTS pvault_rofi_test_targets)
        pvault_warnings(${target})
    endforeach()
endif()

if(BUILD_TESTING)
    add_executable(
        pvault_clipboard_policy_test
        tests/clipboard_policy_test.c
        src/clipboard.c
    )
    target_include_directories(
        pvault_clipboard_policy_test
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_link_libraries(pvault_clipboard_policy_test PRIVATE pvault_core)
    target_compile_definitions(
        pvault_clipboard_policy_test
        PRIVATE
            PVAULT_INSTALLABLE_CLIPBOARD
            "PV_XCLIP_PATH=\"/bin/true\""
    )
    pvault_warnings(pvault_clipboard_policy_test)

    # Persistence fault injection is compiled into a test-only copy of the core.
    # The production binaries always link pvault_core, which has no fault-control
    # API or mutable injection state.
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
    if(pvault_rofi_test_targets)
        list(APPEND pvault_hardened_targets ${pvault_rofi_test_targets})
    endif()
    if(TARGET pvault_core_test)
        list(APPEND pvault_hardened_targets pvault_core_test)
    endif()
    if(TARGET pvault_clipboard_policy_test)
        list(APPEND pvault_hardened_targets pvault_clipboard_policy_test)
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
    if(TARGET pvault_clipboard_policy_test)
        target_link_options(
            pvault_clipboard_policy_test
            PRIVATE -Wl,-z,relro,-z,now -pie
        )
    endif()
    foreach(target IN LISTS pvault_rofi_test_targets)
        target_link_options(${target} PRIVATE -Wl,-z,relro,-z,now -pie)
    endforeach()
endif()

if(PVAULT_ENABLE_SANITIZERS)
    set(pvault_sanitized_targets pvault_core pvault pvault-clip)
    if(pvault_rofi_test_targets)
        list(APPEND pvault_sanitized_targets ${pvault_rofi_test_targets})
    endif()
    if(TARGET pvault_core_test)
        list(APPEND pvault_sanitized_targets pvault_core_test)
    endif()
    if(TARGET pvault_clipboard_policy_test)
        list(APPEND pvault_sanitized_targets pvault_clipboard_policy_test)
    endif()
    foreach(target IN LISTS pvault_sanitized_targets)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endforeach()
endif()

if(PVAULT_ENABLE_LSAN)
    add_library(
        pvault_secure_alloc_tracker
        OBJECT tests/secure_alloc_tracker.c
    )
    pvault_warnings(pvault_secure_alloc_tracker)
    target_compile_options(
        pvault_secure_alloc_tracker
        PRIVATE -fsanitize=leak -fno-omit-frame-pointer
    )
    function(pvault_track_secure_allocations target)
        target_sources(
            ${target}
            PRIVATE $<TARGET_OBJECTS:pvault_secure_alloc_tracker>
        )
        target_link_options(
            ${target}
            PRIVATE
                -Wl,--wrap=sodium_malloc
                -Wl,--wrap=sodium_free
        )
    endfunction()

    set(pvault_lsan_targets pvault_core pvault pvault-clip)
    if(TARGET pvault_rofi_test)
        list(APPEND pvault_lsan_targets
            pvault_rofi_test
            pvault_clip_test
            pvault_clipboard_test_driver
        )
    endif()
    if(TARGET pvault_core_test)
        list(APPEND pvault_lsan_targets pvault_core_test)
    endif()
    if(TARGET pvault_clipboard_policy_test)
        list(APPEND pvault_lsan_targets pvault_clipboard_policy_test)
    endif()
    foreach(target IN LISTS pvault_lsan_targets)
        target_compile_options(${target} PRIVATE -fsanitize=leak -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=leak)
    endforeach()
    foreach(target pvault pvault-clip)
        pvault_track_secure_allocations(${target})
    endforeach()
    if(TARGET pvault_clipboard_policy_test)
        pvault_track_secure_allocations(pvault_clipboard_policy_test)
    endif()
    if(TARGET pvault_rofi_test)
        foreach(target
            pvault_rofi_test
            pvault_clip_test
            pvault_clipboard_test_driver
        )
            pvault_track_secure_allocations(${target})
        endforeach()
    endif()
    if(TARGET pvault_clipboard_test_driver)
        target_compile_definitions(
            pvault_clipboard_test_driver
            PRIVATE PVAULT_TEST_LSAN_EXIT_NORMALIZE
        )
    endif()
endif()

if(BUILD_TESTING)
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)

    add_test(NAME pvault_clipboard_policy_test COMMAND pvault_clipboard_policy_test)
    set_tests_properties(
        pvault_clipboard_policy_test
        PROPERTIES LABELS "unit;security;clipboard-policy" TIMEOUT 30
    )

    if(PVAULT_ENABLE_LSAN)
        add_executable(pvault_lsan_probe tests/lsan_probe.c)
        target_include_directories(
            pvault_lsan_probe
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        target_link_libraries(pvault_lsan_probe PRIVATE pvault_core)
        target_compile_options(
            pvault_lsan_probe
            PRIVATE -fsanitize=leak -fno-omit-frame-pointer
        )
        target_link_options(pvault_lsan_probe PRIVATE -fsanitize=leak)
        pvault_track_secure_allocations(pvault_lsan_probe)
        pvault_warnings(pvault_lsan_probe)
        add_test(
            NAME pvault_lsan_runtime_probe
            COMMAND
                ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/lsan_probe.py
                $<TARGET_FILE:pvault_lsan_probe>
        )
        set_tests_properties(
            pvault_lsan_runtime_probe
            PROPERTIES LABELS "unit;leak-sanitizer;runtime-probe" TIMEOUT 30
        )
    endif()

    add_executable(pvault_tests
        tests/test_util.c
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
    if(PVAULT_ENABLE_LSAN)
        target_compile_options(pvault_tests PRIVATE -fsanitize=leak -fno-omit-frame-pointer)
        target_link_options(pvault_tests PRIVATE -fsanitize=leak)
        target_compile_definitions(
            pvault_tests
            PRIVATE PVAULT_TEST_SECURE_ALLOC_TRACKING
        )
        pvault_track_secure_allocations(pvault_tests)
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

    add_test(
        NAME pvault_external_restore_protocol_unit
        COMMAND
            ${CMAKE_COMMAND} -E env
            "PYTHONDONTWRITEBYTECODE=1"
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/manual/test_external_restore_protocol.py
    )
    set_tests_properties(
        pvault_external_restore_protocol_unit
        PROPERTIES
            LABELS "unit;security;external-restore-parser"
            TIMEOUT 30
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
                "PVAULT_TEST_ROFI_PVAULT=$<TARGET_FILE:pvault_rofi_test>"
                "PVAULT_TEST_SIGNAL_LAUNCHER=$<TARGET_FILE:pvault_signal_launcher>"
                "PVAULT_TEST_CLIPBOARD_DRIVER=$<TARGET_FILE:pvault_clipboard_test_driver>"
                "PVAULT_TEST_CLIPBOARD_OWNER=$<TARGET_FILE:pvault_fake_clipboard_owner>"
                "PVAULT_TEST_CLIPBOARD_HELPER=$<TARGET_FILE:pvault_clip_test>"
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

    if(PVAULT_BUILD_X11_SYSTEM_TESTS OR PVAULT_BUILD_LIVE_X11_CANARY)
        if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
            message(FATAL_ERROR "X11 clipboard test targets currently require Linux")
        endif()
        if(NOT EXISTS "/usr/bin/xclip")
            message(FATAL_ERROR "X11 clipboard test targets require /usr/bin/xclip")
        endif()
        pkg_check_modules(X11 REQUIRED IMPORTED_TARGET x11)
        if(PVAULT_BUILD_LIVE_X11_CANARY)
            pkg_check_modules(XRES REQUIRED IMPORTED_TARGET xres)
        endif()

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
        target_compile_definitions(
            pvault_x11_clipboard_driver
            PRIVATE PVAULT_INSTALLABLE_CLIPBOARD
        )
        pvault_warnings(pvault_x11_clipboard_driver)

        add_executable(
            pvault_x11_selection_owner
            tests/system/x11_selection_owner.c
        )
        target_link_libraries(pvault_x11_selection_owner PRIVATE PkgConfig::X11)
        if(PVAULT_BUILD_LIVE_X11_CANARY)
            target_link_libraries(pvault_x11_selection_owner PRIVATE PkgConfig::XRES)
            target_compile_definitions(
                pvault_x11_selection_owner
                PRIVATE PVAULT_X11_OWNER_PID_QUERY
            )
        endif()
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
        if(PVAULT_ENABLE_LSAN)
            foreach(target pvault_x11_clipboard_driver pvault_x11_selection_owner)
                target_compile_options(
                    ${target}
                    PRIVATE -fsanitize=leak -fno-omit-frame-pointer
                )
                target_link_options(${target} PRIVATE -fsanitize=leak)
            endforeach()
        endif()

        if(PVAULT_BUILD_X11_SYSTEM_TESTS)
            find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
            find_program(PVAULT_XVFB_EXECUTABLE NAMES Xvfb REQUIRED)
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

    if(PVAULT_BUILD_WAYLAND_SYSTEM_TESTS)
        if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
            message(FATAL_ERROR "PVAULT_BUILD_WAYLAND_SYSTEM_TESTS currently requires Linux")
        endif()
        find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
        find_program(PVAULT_WESTON_EXECUTABLE NAMES weston REQUIRED)
        find_program(PVAULT_WL_COPY_EXECUTABLE NAMES wl-copy REQUIRED)
        find_program(PVAULT_WL_PASTE_EXECUTABLE NAMES wl-paste REQUIRED)

        add_executable(
            pvault_wayland_clipboard_driver
            tests/integration/clipboard_driver.c
            src/clipboard.c
        )
        add_executable(
            pvault_wayland_clip_test
            src/clip_main.c
            src/clipboard.c
        )
        target_include_directories(
            pvault_wayland_clipboard_driver
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        target_include_directories(
            pvault_wayland_clip_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        target_link_libraries(pvault_wayland_clipboard_driver PRIVATE pvault_core)
        target_link_libraries(pvault_wayland_clip_test PRIVATE pvault_core)
        target_compile_definitions(
            pvault_wayland_clipboard_driver
            PRIVATE
                PVAULT_EXPERIMENTAL_WAYLAND_CLIPBOARD
                "PV_WL_COPY_PATH=\"${PVAULT_WL_COPY_EXECUTABLE}\""
        )
        target_compile_definitions(
            pvault_wayland_clip_test
            PRIVATE
                PVAULT_EXPERIMENTAL_WAYLAND_CLIPBOARD
                "PV_WL_COPY_PATH=\"${PVAULT_WL_COPY_EXECUTABLE}\""
        )
        set(
            pvault_wayland_test_directory
            "${CMAKE_CURRENT_BINARY_DIR}/private-wayland-test"
        )
        set_target_properties(
            pvault_wayland_clipboard_driver
            PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${pvault_wayland_test_directory}"
        )
        set_target_properties(
            pvault_wayland_clip_test
            PROPERTIES
                OUTPUT_NAME pvault-clip
                RUNTIME_OUTPUT_DIRECTORY "${pvault_wayland_test_directory}"
        )
        add_dependencies(pvault_wayland_clipboard_driver pvault_wayland_clip_test)
        set(
            pvault_wayland_system_targets
            pvault_wayland_clipboard_driver
            pvault_wayland_clip_test
        )
        foreach(target IN LISTS pvault_wayland_system_targets)
            pvault_warnings(${target})
        endforeach()

        if(PVAULT_ENABLE_HARDENING)
            foreach(target IN LISTS pvault_wayland_system_targets)
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
            foreach(target IN LISTS pvault_wayland_system_targets)
                target_compile_options(${target} PRIVATE
                    -fsanitize=address,undefined
                    -fno-omit-frame-pointer
                )
                target_link_options(${target} PRIVATE -fsanitize=address,undefined)
            endforeach()
        endif()
        if(PVAULT_ENABLE_LSAN)
            foreach(target IN LISTS pvault_wayland_system_targets)
                target_compile_options(
                    ${target}
                    PRIVATE -fsanitize=leak -fno-omit-frame-pointer
                )
                target_link_options(${target} PRIVATE -fsanitize=leak)
                pvault_track_secure_allocations(${target})
            endforeach()
            target_compile_definitions(
                pvault_wayland_clipboard_driver
                PRIVATE PVAULT_TEST_LSAN_EXIT_NORMALIZE
            )
        endif()

        add_test(
            NAME pvault_wayland_system_tests
            COMMAND
                ${CMAKE_COMMAND} -E env
                "PVAULT_WAYLAND_DRIVER=$<TARGET_FILE:pvault_wayland_clipboard_driver>"
                "PVAULT_WESTON=${PVAULT_WESTON_EXECUTABLE}"
                "PVAULT_WL_COPY=${PVAULT_WL_COPY_EXECUTABLE}"
                "PVAULT_WL_PASTE=${PVAULT_WL_PASTE_EXECUTABLE}"
                ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/system/test_wlcopy_wayland.py
        )
        set_tests_properties(
            pvault_wayland_system_tests
            PROPERTIES
                LABELS "system;security-characterization;wayland;non-installable"
                TIMEOUT 45
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

if(PVAULT_ENABLE_LSAN)
    install(CODE [[
        message(FATAL_ERROR "The LeakSanitizer test profile is not installable")
    ]])
else()
    install(TARGETS pvault pvault-clip RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES docs/pvault.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 OPTIONAL)
    install(FILES LICENSE COPYRIGHT DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/licenses/pvault)
    install(FILES
        README.md
        SECURITY.md
        THREAT_MODEL.md
        CONTRIBUTING.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}
    )
    install(FILES
        docs/FORMAT.md
        docs/COMPATIBILITY.md
        docs/ARCHITECTURE.pt-BR.md
        docs/ROADMAP.pt-BR.md
        docs/RELEASES.md
        docs/EXTERNAL_RESTORE.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/docs
    )
endif()
