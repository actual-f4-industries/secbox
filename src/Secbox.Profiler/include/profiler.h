// Public surface of the Secbox CLR Profiler.
//
// The profiler is loaded by CoreCLR via either:
//   - environment variables at process start (CORECLR_ENABLE_PROFILING=1,
//     CORECLR_PROFILER={SECBOX_PROFILER_CLSID}, CORECLR_PROFILER_PATH=...)
//   - DiagnosticsClient.AttachProfiler from inside the editor process
//     (attach mode — the default deployment).
//
// Once loaded, managed code (Secbox.Core/RuntimeSensors/Sensors/
// ProfilerSensor.cs) registers a callback via Secbox_RegisterCallback. The
// profiler delivers normalized JSON event payloads to that callback.

#pragma once

#include <cstdint>

#if defined(_WIN32)
    #define SECBOX_API extern "C" __declspec(dllexport)
    #define SECBOX_CALL __stdcall
#else
    #define SECBOX_API extern "C" __attribute__((visibility("default")))
    #define SECBOX_CALL
#endif

// COM CLSID published by the profiler. The CoreCLR loader matches against
// CORECLR_PROFILER (start mode) or the attach-mode arguments.
//
//   {53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101}
#define SECBOX_PROFILER_CLSID_STR "{53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101}"

// Event kinds that match Secbox.Sentinel.Contracts.KernelEventKind in spirit
// but apply to managed-runtime observation only.
enum SecboxProfilerEventKind : int32_t {
    EK_Unknown                 = 0,
    EK_AssemblyLoad            = 1000,
    EK_ModuleLoad              = 1001,
    EK_JitCompilationStarted   = 1002,
    EK_DynamicMethodJit        = 1003,
    EK_ExceptionThrown         = 1004,
    EK_ProfilerAttached        = 9000,
    EK_ProfilerDetaching       = 9001,
};

// Managed callback signature. Payload is a UTF-16 JSON string owned by the
// profiler — must be copied by the managed side before returning.
typedef void (SECBOX_CALL *SecboxEventCallback)(
    int32_t kind,
    const wchar_t* payload_json);

// Register / unregister the managed callback. Calling Register a second time
// replaces the previous callback. Unregister with nullptr is also valid and
// is what ProfilerSensor calls on shutdown.
SECBOX_API void SECBOX_CALL Secbox_RegisterCallback(SecboxEventCallback cb);

// Status query — returns a bitfield: bit0=initialized, bit1=callback set,
// bit2=ring overflow seen since boot.
SECBOX_API int32_t SECBOX_CALL Secbox_GetStatus();

// Synchronous flush of the pre-callback ring buffer. Used by managed init
// right after registering its callback to receive events that fired before
// the callback was wired.
SECBOX_API void SECBOX_CALL Secbox_DrainRing();
