using Secbox.Contracts;
using Secbox.Scanner.Finders;

namespace Secbox.Scanner.Pipeline;

// Factory for the built-in finder set. Consumers can pull a subset or extend
// with custom IFinder implementations.
public static class FinderRegistry
{
    public static IFinder Metadata() => new MetadataFinder();
    public static IFinder Il() => new IlFinder();
    public static IFinder Source() => new SourceFinder();
    public static IFinder NativeBinary() => new NativeBinaryFinder();

    public static IReadOnlyList<IFinder> All() => new IFinder[]
    {
        Metadata(),
        Il(),
        Source(),
        NativeBinary(),
    };
}
