using Secbox.Contracts;
using Secbox.Rules.Packs;
using Secbox.Scanner.Pipeline;

namespace Secbox.Core;

// Default wiring. Composes the built-in finder set and rule pack registry
// into a ScanPipeline. Consumers needing custom finders/packs construct a
// ScanPipeline directly; the editor adapter uses this static default.
public static class Bootstrap
{
    static readonly Lazy<IPipeline> _default = new(BuildDefault);

    public static IPipeline DefaultPipeline => _default.Value;

    public static IPipeline BuildDefault() => new ScanPipeline(
        finders: FinderRegistry.All(),
        rulePacks: PackRegistry.All());
}
