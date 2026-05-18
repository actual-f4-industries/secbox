using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Collection;

public sealed class ImageLoadProvider : IKernelProvider
{
    public ProviderKind Kind => ProviderKind.ImageLoad;

    public KernelTraceEventParser.Keywords Keywords =>
        KernelTraceEventParser.Keywords.ImageLoad;

    public void Subscribe(KernelTraceEventParser parser, IKernelEventSink sink)
    {
        parser.ImageLoad += (ImageLoadTraceData d) =>
            sink.Publish(new KernelEvent(
                Sequence: 0,
                Kind: KernelEventKind.ImageLoad,
                Timestamp: new DateTimeOffset(d.TimeStamp.ToUniversalTime(), TimeSpan.Zero),
                Pid: d.ProcessID,
                Tid: d.ThreadID,
                Path: d.FileName,
                Target: null,
                Extras: new Dictionary<string, string>
                {
                    ["imageBase"] = "0x" + d.ImageBase.ToString("x"),
                    ["imageSize"] = d.ImageSize.ToString(),
                },
                UserStack: null));
    }
}
