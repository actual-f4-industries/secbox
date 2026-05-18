using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Collection;

// One provider per ETW kernel surface (File, Process, Network, Registry,
// ImageLoad). Each is responsible for:
//   - Declaring its KernelTraceEventParser.Keywords contribution.
//   - Subscribing to the parser's typed events when the collector starts.
//   - Normalizing each event into KernelEvent and forwarding to the sink.
// Keeping providers behind this contract lets us add new ETW surfaces (or
// swap to an alternative collector like a custom EventListener-based one)
// without changing the collector loop.
public interface IKernelProvider
{
    ProviderKind Kind { get; }

    // ETW kernel keywords contributed when this provider is registered.
    // KernelTraceEventParser.Keywords is a flags enum — the collector ORs all
    // active providers' keywords into the single kernel session.
    KernelTraceEventParser.Keywords Keywords { get; }

    // Wire up event handlers on the given parser. The provider should call
    // sink.Publish(KernelEvent) for every event it cares about.
    void Subscribe(KernelTraceEventParser parser, IKernelEventSink sink);
}

public interface IKernelEventSink
{
    void Publish(KernelEvent ev);
}
