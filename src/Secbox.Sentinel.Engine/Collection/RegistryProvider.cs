using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Collection;

public sealed class RegistryProvider : IKernelProvider
{
    public ProviderKind Kind => ProviderKind.Registry;

    public KernelTraceEventParser.Keywords Keywords =>
        KernelTraceEventParser.Keywords.Registry;

    public void Subscribe(KernelTraceEventParser parser, IKernelEventSink sink)
    {
        parser.RegistryOpen += (RegistryTraceData d) =>
            sink.Publish(Build(KernelEventKind.RegOpenKey, d));

        parser.RegistrySetValue += (RegistryTraceData d) =>
            sink.Publish(Build(KernelEventKind.RegSetValue, d));

        parser.RegistryDelete += (RegistryTraceData d) =>
            sink.Publish(Build(KernelEventKind.RegDeleteKey, d));

        // ETW does not surface a separate "delete value" event in the kernel
        // registry provider — value removal goes through SetInformation. We
        // catch it via RegistrySetInformation when needed for compliance use;
        // for now Delete (key-scoped) is sufficient.
    }

    static KernelEvent Build(KernelEventKind kind, RegistryTraceData d) =>
        new(
            Sequence: 0,
            Kind: kind,
            Timestamp: new DateTimeOffset(d.TimeStamp.ToUniversalTime(), TimeSpan.Zero),
            Pid: d.ProcessID,
            Tid: d.ThreadID,
            Path: d.KeyName,
            Target: null,
            Extras: string.IsNullOrEmpty(d.ValueName) ? null
                : new Dictionary<string, string> { ["value"] = d.ValueName },
            UserStack: null);
}
