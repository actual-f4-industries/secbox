// Small lock-free SPSC ring used to buffer events that fire before the
// managed callback is registered. Sized small on purpose — a few hundred
// events worth, anything older drops. Once the callback is set, the ring
// is drained and bypassed.

#pragma once
#include <atomic>
#include <cstdint>
#include <string>

namespace secbox {

struct RingEntry {
    int32_t kind;
    std::wstring payload;
};

class EventRing {
public:
    static constexpr size_t Capacity = 256;

    bool TryPush(int32_t kind, std::wstring&& payload);
    bool TryPop(RingEntry& out);
    bool Overflowed() const { return overflowed_.load(std::memory_order_relaxed); }
    size_t Count() const {
        auto h = head_.load(std::memory_order_acquire);
        auto t = tail_.load(std::memory_order_acquire);
        return h - t;
    }

private:
    RingEntry slots_[Capacity];
    std::atomic<uint64_t> head_{0};
    std::atomic<uint64_t> tail_{0};
    std::atomic<bool> overflowed_{false};
};

extern EventRing g_pre_callback_ring;

} // namespace secbox
