#include "event_ring.h"

namespace secbox {

EventRing g_pre_callback_ring;

bool EventRing::TryPush(int32_t kind, std::wstring&& payload) {
    auto h = head_.load(std::memory_order_relaxed);
    auto t = tail_.load(std::memory_order_acquire);
    if (h - t >= Capacity) {
        overflowed_.store(true, std::memory_order_relaxed);
        return false;
    }
    auto& slot = slots_[h % Capacity];
    slot.kind = kind;
    slot.payload = std::move(payload);
    head_.store(h + 1, std::memory_order_release);
    return true;
}

bool EventRing::TryPop(RingEntry& out) {
    auto t = tail_.load(std::memory_order_relaxed);
    auto h = head_.load(std::memory_order_acquire);
    if (t == h) return false;
    auto& slot = slots_[t % Capacity];
    out.kind = slot.kind;
    out.payload = std::move(slot.payload);
    tail_.store(t + 1, std::memory_order_release);
    return true;
}

} // namespace secbox
