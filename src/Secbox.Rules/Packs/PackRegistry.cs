using Secbox.Contracts;

namespace Secbox.Rules.Packs;

// Factory for the built-in rule packs. Consumers can pull a subset
// (e.g. CLI may want everything; editor adapter may only want Critical).
public static class PackRegistry
{
    public static IRulePack Critical() => new CriticalPack();
    public static IRulePack NativeBinary() => new NativeBinaryPack();

    public static IReadOnlyList<IRulePack> All() => new[]
    {
        Critical(),
        NativeBinary(),
    };
}
