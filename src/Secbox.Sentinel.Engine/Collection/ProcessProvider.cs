using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Collection;

public sealed class ProcessProvider : IKernelProvider
{
    public ProviderKind Kind => ProviderKind.Process;

    public KernelTraceEventParser.Keywords Keywords =>
        KernelTraceEventParser.Keywords.Process;

    public void Subscribe(KernelTraceEventParser parser, IKernelEventSink sink)
    {
        parser.ProcessStart += (ProcessTraceData d) =>
            sink.Publish(new KernelEvent(
                Sequence: 0,
                Kind: KernelEventKind.ProcessStart,
                Timestamp: new DateTimeOffset(d.TimeStamp.ToUniversalTime(), TimeSpan.Zero),
                Pid: d.ProcessID,
                Tid: d.ThreadID,
                Path: d.ImageFileName,
                Target: null,
                Extras: new Dictionary<string, string>
                {
                    ["commandLine"] = d.CommandLine ?? "",
                    ["parentPid"] = d.ParentID.ToString(),
                },
                UserStack: null));

        parser.ProcessStop += (ProcessTraceData d) =>
            sink.Publish(new KernelEvent(
                Sequence: 0,
                Kind: KernelEventKind.ProcessStop,
                Timestamp: new DateTimeOffset(d.TimeStamp.ToUniversalTime(), TimeSpan.Zero),
                Pid: d.ProcessID,
                Tid: d.ThreadID,
                Path: d.ImageFileName,
                Target: null,
                Extras: new Dictionary<string, string> { ["exitCode"] = d.ExitStatus.ToString() },
                UserStack: null));
    }
}
