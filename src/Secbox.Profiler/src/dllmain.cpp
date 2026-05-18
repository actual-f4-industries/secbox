#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Minimal DllMain. The profiler does no per-thread bookkeeping and no
// process-attach work — registration and class-factory creation happen
// on-demand via DllGetClassObject when CoreCLR loads us.
BOOL APIENTRY DllMain(HMODULE /*h*/, DWORD reason, LPVOID /*reserved*/) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

#else // POSIX

// Linux/macOS shim — the constructor/destructor are no-ops; mirrored to
// keep behaviour parity with Windows.
__attribute__((constructor)) static void secbox_profiler_init(void) {}
__attribute__((destructor))  static void secbox_profiler_fini(void) {}

#endif
