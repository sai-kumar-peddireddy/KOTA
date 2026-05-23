cmake_minimum_required(VERSION 3.25)
project(KOTA VERSION 0.1.0 LANGUAGES CXX C)

# ─── C++23 ───────────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "13.0")
    message(FATAL_ERROR "KOTA requires GCC 13+ (std::expected, etc.)")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17.0")
    message(FATAL_ERROR "KOTA requires Clang 17+ for C++23")
endif()

# ─── Tools ───────────────────────────────────────────────────────────────────
find_program(CLANG_BPF clang REQUIRED DOC "clang for BPF target compilation")
find_program(BPFTOOL bpftool REQUIRED DOC "bpftool for skeleton generation")

execute_process(
    COMMAND ${CLANG_BPF} --version
    OUTPUT_VARIABLE _clang_ver_out
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCH "version ([0-9]+)" _clang_ver_match "${_clang_ver_out}")
set(CLANG_BPF_MAJOR "${CMAKE_MATCH_1}")
if(CLANG_BPF_MAJOR LESS 15)
    message(FATAL_ERROR
        "KOTA requires clang 15+ for BPF CO-RE (found major ${CLANG_BPF_MAJOR})")
endif()
message(STATUS "Using clang ${CLANG_BPF_MAJOR} for BPF bytecode")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
option(KOTA_OTEL "Enable OpenTelemetry C++ metrics SDK integration" ON)

# BPF pt_regs / context layout follows the *host* architecture libbpf expects.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64|arm64|ARM64")
    set(KOTA_BPF_ARCH_DEFINE "__TARGET_ARCH_arm64")
else()
    set(KOTA_BPF_ARCH_DEFINE "__TARGET_ARCH_x86")
endif()

# ─── CO-RE: vmlinux.h from running kernel BTF ────────────────────────────────
set(VMLINUX_H "${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h")
add_custom_command(
    OUTPUT "${VMLINUX_H}"
    COMMAND "${BPFTOOL}" btf dump file /sys/kernel/btf/vmlinux format c
            > "${VMLINUX_H}"
    COMMENT "CO-RE: generating vmlinux.h from /sys/kernel/btf/vmlinux"
    VERBATIM
)

# ─── BPF: .bpf.c → .bpf.o + bpftool skeleton ───────────────────────────────
# Outputs live in CMAKE_CURRENT_BINARY_DIR. Policy + profile parsing use yaml-cpp.
function(bpf_program NAME SOURCE)
    set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE}")
    set(OBJ "${CMAKE_CURRENT_BINARY_DIR}/${NAME}.bpf.o")
    set(SKEL "${CMAKE_CURRENT_BINARY_DIR}/${NAME}.skel.h")

    add_custom_command(
        OUTPUT "${OBJ}"
        COMMAND
            "${CLANG_BPF}"
            -target bpf
            "-D${KOTA_BPF_ARCH_DEFINE}"
            -g
            -O2
            -I "${CMAKE_CURRENT_BINARY_DIR}"
            -I "${CMAKE_CURRENT_SOURCE_DIR}/include/shared"
            -I /usr/include
            -c "${SRC}" -o "${OBJ}"
        DEPENDS
            "${SRC}"
            "${VMLINUX_H}"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/shared/kota_common.h"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/maps/kota_maps.h"
        COMMENT "BPF compile: ${NAME}.bpf.c → ${NAME}.bpf.o"
        VERBATIM
    )

    add_custom_command(
        OUTPUT "${SKEL}"
        COMMAND sh -c "${BPFTOOL} gen skeleton ${OBJ} name ${NAME} > ${SKEL}"
        DEPENDS "${OBJ}"
        COMMENT "BPF skeleton: ${NAME}.skel.h"
        VERBATIM
    )

    set(${NAME}_BPF_OBJ "${OBJ}" PARENT_SCOPE)
    set(${NAME}_BPF_SKEL "${SKEL}" PARENT_SCOPE)
endfunction()

bpf_program(lifecycle src/bpf/programs/lifecycle.bpf.c)
bpf_program(scalpel src/bpf/programs/scalpel.bpf.c)
bpf_program(veto src/bpf/programs/veto.bpf.c)
bpf_program(ioctl_observer src/bpf/programs/ioctl_observer.bpf.c)

add_custom_target(
    kota-bpf ALL
    DEPENDS
        "${lifecycle_BPF_SKEL}"
        "${scalpel_BPF_SKEL}"
        "${veto_BPF_SKEL}"
        "${ioctl_observer_BPF_SKEL}"
    COMMENT "All BPF skeleton headers generated"
)

# ─── kotad (Community Edition sentinel) ──────────────────────────────────────
set(
    SENTINEL_SOURCES
    src/sentinel/core/main.cpp
    src/sentinel/core/control_plane_server.cpp
    src/sentinel/core/kotad_runtime.cpp
    src/sentinel/core/kotad_ring_dispatch.cpp
    src/sentinel/core/kotad_nvml_monitor.cpp
    src/sentinel/core/attach_manager.cpp
    src/sentinel/maps/bpf_loader.cpp
    src/sentinel/maps/map_updater.cpp
    src/sentinel/identity/ringbuf_consumer.cpp
    src/sentinel/identity/cilium_endpoint_client.cpp
    src/sentinel/identity/pod_resolver.cpp
    src/sentinel/identity/cilium_peeker.cpp
    src/sentinel/policy/profile_schema.cpp
    src/sentinel/policy/decision_engine.cpp
    src/sentinel/policy/profile_registry.cpp
    src/sentinel/policy/profile_store.cpp
    src/sentinel/telemetry/nvml_poller.cpp
    src/sentinel/telemetry/otel_exporter.cpp
    src/sentinel/telemetry/violation_logger.cpp
    ../api/gen/cpp/kota_control_plane.pb.cc
    ../api/gen/cpp/kota_control_plane.grpc.pb.cc
)

add_executable(kotad ${SENTINEL_SOURCES})

target_compile_options(kotad PRIVATE -Wall -Wextra -Werror)

target_include_directories(
    kotad
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include/shared"
        "${CMAKE_CURRENT_BINARY_DIR}"
)

find_package(yaml-cpp CONFIG QUIET)
if (NOT TARGET yaml-cpp::yaml-cpp)
    include(FetchContent)
    message(STATUS
            "yaml-cpp: FetchContent (install libyaml-cpp-dev + CMake config for a "
            "faster, system build)")
    FetchContent_Declare(
        yaml-cpp
        GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
        GIT_TAG 0.8.0
    )
    set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "yaml-cpp" FORCE)
    set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "yaml-cpp" FORCE)
    set(YAML_CPP_FORMAT_SOURCE OFF CACHE BOOL "yaml-cpp" FORCE)
    set(YAML_CPP_INSTALL OFF CACHE BOOL "yaml-cpp" FORCE)
    set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "yaml-cpp" FORCE)
    set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "yaml-cpp" FORCE)
    FetchContent_MakeAvailable(yaml-cpp)
endif()
if (NOT TARGET yaml-cpp::yaml-cpp)
    message(FATAL_ERROR "KOTA: yaml-cpp target not available (network for FetchContent or "
                       "set yaml-cpp_DIR to a CMake package dir)")
endif()

find_package(nlohmann_json 3.11.0 QUIET CONFIG)
if (NOT TARGET nlohmann_json::nlohmann_json)
    include(FetchContent)
    message(STATUS
            "nlohmann/json: FetchContent (install nlohmann-json3-dev for a system build)")
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
        GIT_SHALLOW TRUE
    )
    set(JSON_Install OFF CACHE BOOL "nlohmann_json" FORCE)
    set(JSON_BuildTests OFF CACHE BOOL "nlohmann_json" FORCE)
    FetchContent_MakeAvailable(nlohmann_json)
endif()
if (NOT TARGET nlohmann_json::nlohmann_json)
    message(FATAL_ERROR "KOTA: nlohmann_json not available (network for FetchContent or "
                       "set nlohmann_json_DIR to a CMake package dir)")
endif()

if(KOTA_OTEL)
    include(FetchContent)
    # v1.17.0 pin keeps API/SDK symbols stable; flags keep build small and metrics-only.
    FetchContent_Declare(
        opentelemetry-cpp
        GIT_REPOSITORY https://github.com/open-telemetry/opentelemetry-cpp.git
        GIT_TAG v1.17.0
    )
    set(BUILD_TESTING OFF CACHE BOOL "opentelemetry-cpp" FORCE)
    set(WITH_EXAMPLES OFF CACHE BOOL "opentelemetry-cpp" FORCE)
    set(WITH_BENCHMARK OFF CACHE BOOL "opentelemetry-cpp" FORCE)
    set(WITH_OTLP_HTTP ON CACHE BOOL "opentelemetry-cpp" FORCE)
    set(WITH_OTLP_GRPC OFF CACHE BOOL "opentelemetry-cpp" FORCE)
    set(WITH_PROMETHEUS OFF CACHE BOOL "opentelemetry-cpp" FORCE)
    set(WITH_METRICS_PREVIEW ON CACHE BOOL "opentelemetry-cpp" FORCE)
    set(WITH_METRICS_EXEMPLAR_PREVIEW OFF CACHE BOOL "opentelemetry-cpp" FORCE)
    FetchContent_MakeAvailable(opentelemetry-cpp)
endif()
find_library(NVML_LIB nvidia-ml)
if(NVML_LIB)
    message(STATUS "Found NVML library: ${NVML_LIB}")
else()
    message(STATUS "NVML library not found; kotad will use runtime dlopen only")
endif()
target_link_libraries(kotad PRIVATE PkgConfig::LIBBPF yaml-cpp::yaml-cpp
                                    nlohmann_json::nlohmann_json
                                    ${CMAKE_DL_LIBS})
if(KOTA_OTEL)
    target_compile_definitions(kotad PRIVATE KOTA_OTEL=1)
    set(_kota_otel_linked FALSE)
    if(TARGET opentelemetry_metrics)
        target_link_libraries(kotad PRIVATE opentelemetry_metrics)
        set(_kota_otel_linked TRUE)
    endif()
    if(TARGET opentelemetry_sdk)
        target_link_libraries(kotad PRIVATE opentelemetry_sdk)
        set(_kota_otel_linked TRUE)
    endif()
    if(TARGET opentelemetry_resources)
        target_link_libraries(kotad PRIVATE opentelemetry_resources)
        set(_kota_otel_linked TRUE)
    endif()
    if(TARGET opentelemetry_exporter_otlp_http_metric)
        target_link_libraries(kotad PRIVATE opentelemetry_exporter_otlp_http_metric)
        set(_kota_otel_linked TRUE)
    endif()
    if(NOT _kota_otel_linked)
        message(FATAL_ERROR
            "KOTA_OTEL=ON but no opentelemetry-cpp metrics/sdk targets were found")
    endif()
else()
    target_compile_definitions(kotad PRIVATE KOTA_OTEL=0)
endif()
if(NVML_LIB)
    target_link_libraries(kotad PRIVATE ${NVML_LIB})
endif()

find_package(Threads REQUIRED)
target_link_libraries(kotad PRIVATE Threads::Threads)

pkg_check_modules(GRPCPP REQUIRED IMPORTED_TARGET grpc++)
target_link_libraries(kotad PRIVATE PkgConfig::GRPCPP)

add_dependencies(kotad kota-bpf)

install(TARGETS kotad RUNTIME DESTINATION bin)

# Pod resolver: cgroup/container ID + pod UID parse tests (same TU as kotad).
include(CTest)
add_executable(
    pod_resolver_parse_test
    src/sentinel/maps/map_updater.cpp
    src/sentinel/identity/cilium_endpoint_client.cpp
    src/sentinel/identity/pod_resolver.cpp
    src/sentinel/policy/profile_registry.cpp
    src/sentinel/policy/profile_schema.cpp
)
target_compile_definitions(
    pod_resolver_parse_test
    PRIVATE
        KOTA_BUILD_POD_RESOLVER_PARSE_UNIT_TEST=1
)
target_compile_options(pod_resolver_parse_test PRIVATE -Wall -Wextra -Werror)
target_include_directories(
    pod_resolver_parse_test
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include/shared"
        "${CMAKE_CURRENT_BINARY_DIR}"
)
target_link_libraries(
    pod_resolver_parse_test
    PRIVATE PkgConfig::LIBBPF nlohmann_json::nlohmann_json Threads::Threads
            yaml-cpp::yaml-cpp ${CMAKE_DL_LIBS}
)
add_test(NAME pod_resolver_parse COMMAND pod_resolver_parse_test)

# Pod resolver: OCI config.json → kota.ai/profile golden (committed fixture).
add_executable(
    pod_resolver_oci_profile_golden_test
    src/sentinel/maps/map_updater.cpp
    src/sentinel/identity/cilium_endpoint_client.cpp
    src/sentinel/identity/pod_resolver.cpp
    src/sentinel/policy/profile_registry.cpp
    src/sentinel/policy/profile_schema.cpp
)
target_compile_definitions(
    pod_resolver_oci_profile_golden_test
    PRIVATE
        KOTA_BUILD_POD_RESOLVER_OCI_PROFILE_GOLDEN_TEST=1
        "KOTA_OCI_CONFIG_JSON_FIXTURE_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/../tests/fixtures/oci/kota_profile_label_golden.json\""
)
target_compile_options(pod_resolver_oci_profile_golden_test PRIVATE -Wall -Wextra
                                                                     -Werror)
target_include_directories(
    pod_resolver_oci_profile_golden_test
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include/shared"
        "${CMAKE_CURRENT_BINARY_DIR}"
)
target_link_libraries(
    pod_resolver_oci_profile_golden_test
    PRIVATE PkgConfig::LIBBPF nlohmann_json::nlohmann_json Threads::Threads
            yaml-cpp::yaml-cpp ${CMAKE_DL_LIBS}
)
add_test(NAME pod_resolver_oci_profile_golden
         COMMAND pod_resolver_oci_profile_golden_test)

# Policy: YAML profile schema + decision engine (fixture-driven).
add_executable(
    policy_profile_decision_test
    src/sentinel/policy/policy_profile_decision_test.cpp
    src/sentinel/policy/profile_schema.cpp
    src/sentinel/policy/decision_engine.cpp
)
target_compile_definitions(
    policy_profile_decision_test
    PRIVATE
        "KOTA_POLICY_PROFILE_FIXTURE_ROOT=\"${CMAKE_CURRENT_SOURCE_DIR}/../tests/fixtures/profiles\""
)
target_compile_options(policy_profile_decision_test PRIVATE -Wall -Wextra -Werror)
target_include_directories(
    policy_profile_decision_test
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include/shared"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/sentinel/policy"
)
target_link_libraries(policy_profile_decision_test PRIVATE yaml-cpp::yaml-cpp)
add_test(NAME policy_profile_decision COMMAND policy_profile_decision_test)
