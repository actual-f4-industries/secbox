namespace Secbox.Sentinel.Contracts;

// Bitmask of kernel providers a subscriber wants. Pure bitmask so a client
// can request multiple in one Subscribe message. Service may report a
// narrower mask back in SubscribeAck if a provider is unavailable on the
// host.
[Flags]
public enum ProviderKind
{
    None = 0,
    File = 1 << 0,
    Process = 1 << 1,
    Network = 1 << 2,
    Registry = 1 << 3,
    ImageLoad = 1 << 4,

    All = File | Process | Network | Registry | ImageLoad,
}
