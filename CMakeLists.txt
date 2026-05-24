cmake_minimum_required(VERSION 3.25)

# KOTA workspace root — primary build lives under kota/.
# ACCEPT: cmake -S . -B build && cmake --build build
#
# libbpf is resolved via pkg-config inside kota/CMakeLists.txt. To use vcpkg
# instead, add kota/vcpkg.json and pass -DCMAKE_TOOLCHAIN_FILE=.../vcpkg.cmake;
# VCPKG_MANIFEST_DIR is preset when that manifest exists.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/kota/vcpkg.json")
    set(VCPKG_MANIFEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/kota"
        CACHE PATH "vcpkg manifest directory (kota/vcpkg.json)")
endif()

project(KOTA-workspace LANGUAGES NONE)

enable_testing()

add_subdirectory(kota)
