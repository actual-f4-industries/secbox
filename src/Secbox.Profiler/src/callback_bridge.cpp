#include "profiler.h"
#include "event_ring.h"

#include <atomic>
#include <mutex>

namespace secbox {

namespace {
    std::atomic<SecboxEventCallback> g_callback{nullptr};
    std::atomic<bool> g_initialized{false};
    std::mutex g_drain_lock;  // serialise drain calls
}

void SetInitialized(bool v) { g_initialized.store(v, std::memory_order_release); }
bool IsInitialized() { return g_initialized.load(std::memory_order_acquire); }

void Emit(int32_t kind, std::wstring payload) {
    auto cb = g_callback.load(std::memory_order_acquire);
    if (cb != nullptr) {
        // Direct dispatch. Caller of the callback (managed side) is
        // responsible for never throwing back into native — exceptions out
        // of a CoreCLR callback into native code are undefined.
        try { cb(kind, payload.c_str()); } catch (...) { /* swallow */ }
        return;
    }
    // No callback yet — buffer.
    (void)g_pre_callback_ring.TryPush(kind, std::move(payload));
}

void DrainRingToCallback() {
    std::lock_guard<std::mutex> lk(g_drain_lock);
    auto cb = g_callback.load(std::memory_order_acquire);
    if (cb == nullptr) return;
    RingEntry entry;
    while (g_pre_callback_ring.TryPop(entry)) {
        try { cb(entry.kind, entry.payload.c_str()); } catch (...) { /* swallow */ }
    }
}

} // namespace secbox

extern "C" {

SECBOX_API void SECBOX_CALL Secbox_RegisterCallback(SecboxEventCallback cb) {
    secbox::g_callback.store(cb, std::memory_order_release);
    if (cb != nullptr) secbox::DrainRingToCallback();
}

SECBOX_API int32_t SECBOX_CALL Secbox_GetStatus() {
    int32_t s = 0;
    if (secbox::IsInitialized()) s |= 0x1;
    if (secbox::g_callback.load(std::memory_order_acquire) != nullptr) s |= 0x2;
    if (secbox::g_pre_callback_ring.Overflowed()) s |= 0x4;
    return s;
}

SECBOX_API void SECBOX_CALL Secbox_DrainRing() {
    secbox::DrainRingToCallback();
}

} // extern "C"
