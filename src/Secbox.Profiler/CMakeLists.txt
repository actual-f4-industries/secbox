cmake_minimum_required(VERSION 3.20)
project(secbox_profiler LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Static CRT linkage (/MT, /MTd). Default MSVC is dynamic CRT (/MD) which
# requires vcruntime140.dll + msvcp140.dll from the Visual C++ Redistributable
# on the target machine. That's not bundled by the .NET runtime and not a
# given on every user's box — missing CRT manifests as 0x8007007E "Unable
# to load DLL or one of its dependencies" when the profiler P/Invokes fire.
# Static linkage bundles the CRT into our DLL (adds ~150KB).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---------------------------------------------------------------------------
# CoreCLR profiler API headers.
#
# These are NOT shipped with the .NET SDK installer — we vendor them from
# dotnet/runtime under externals/coreclr-pal-headers/. The release workflow
# pulls the right set on first checkout. Headers needed:
#   corprof.h, corprof.idl-generated, cor.h, corhdr.h, corerror.h
# ---------------------------------------------------------------------------
set(CORECLR_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/externals/coreclr-pal-headers"
    CACHE PATH "Path to vendored CoreCLR profiler API headers")

if(NOT EXISTS "${CORECLR_HEADERS}/corprof.h")
    message(WARNING
        "CoreCLR profiler headers not found at ${CORECLR_HEADERS}. "
        "Run scripts/fetch-coreclr-headers.ps1 (or scripts/fetch-coreclr-headers.sh on linux) "
        "to vendor them before configuring.")
endif()

# ---------------------------------------------------------------------------
# Platform shim
# ---------------------------------------------------------------------------
if(WIN32)
    set(SECBOX_PROFILER_OUTPUT_NAME "secbox-profiler-win-x64")
    add_definitions(-DBIT64 -DHOST_64BIT -D_AMD64_ -DAMD64)
elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(SECBOX_PROFILER_OUTPUT_NAME "secbox-profiler-osx-arm64")
    else()
        set(SECBOX_PROFILER_OUTPUT_NAME "secbox-profiler-osx-x64")
    endif()
    add_definitions(-DPAL_STDCPP_COMPAT -DBIT64 -DHOST_64BIT)
else()
    set(SECBOX_PROFILER_OUTPUT_NAME "secbox-profiler-linux-x64")
    add_definitions(-DPAL_STDCPP_COMPAT -DBIT64 -DHOST_64BIT)
endif()

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
add_library(secbox_profiler SHARED
    src/dllmain.cpp
    src/profiler.cpp
    src/callback_bridge.cpp
    src/event_ring.cpp
)

target_include_directories(secbox_profiler
    PRIVATE
        include
        "${CORECLR_HEADERS}"
)

set_target_properties(secbox_profiler PROPERTIES
    OUTPUT_NAME "${SECBOX_PROFILER_OUTPUT_NAME}"
    PREFIX ""
    DEFINE_SYMBOL "SECBOX_PROFILER_EXPORTS"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

if(WIN32)
    target_link_libraries(secbox_profiler PRIVATE ole32 advapi32)
    target_compile_options(secbox_profiler PRIVATE /W4 /GS /sdl /guard:cf)
    target_link_options(secbox_profiler PRIVATE /GUARD:CF /DYNAMICBASE /NXCOMPAT)
else()
    target_compile_options(secbox_profiler PRIVATE
        -Wall -Wextra -fstack-protector-strong -fvisibility=hidden)
endif()

install(TARGETS secbox_profiler RUNTIME DESTINATION bin LIBRARY DESTINATION bin)
