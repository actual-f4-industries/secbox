using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Collection;

// Subscribes to FileIO_V3 events — Create/Write/Delete/Rename/SetSecurity.
// Read events are NOT enabled by default: editor.exe does thousands of
// file-reads per second during asset loading, swamping any downstream
// consumer. Read coverage can be opted into per-subscription later if a
// specific investigation needs it.
public sealed class FileProvider : IKernelProvider
{
    public ProviderKind Kind => ProviderKind.File;

    public KernelTraceEventParser.Keywords Keywords =>
        KernelTraceEventParser.Keywords.FileIOInit;

    public void Subscribe(KernelTraceEventParser parser, IKernelEventSink sink)
    {
        parser.FileIOCreate += (FileIOCreateTraceData d) =>
            sink.Publish(Build(KernelEventKind.FileCreate, d.ProcessID, d.ThreadID, d.TimeStamp, d.FileName));

        parser.FileIODelete += (FileIOInfoTraceData d) =>
            sink.Publish(Build(KernelEventKind.FileDelete, d.ProcessID, d.ThreadID, d.TimeStamp, d.FileName));

        parser.FileIOWrite += (FileIOReadWriteTraceData d) =>
            sink.Publish(Build(KernelEventKind.FileWrite, d.ProcessID, d.ThreadID, d.TimeStamp, d.FileName));

        parser.FileIORename += (FileIOInfoTraceData d) =>
            sink.Publish(Build(KernelEventKind.FileRename, d.ProcessID, d.ThreadID, d.TimeStamp, d.FileName));

        parser.FileIOSetInfo += (FileIOInfoTraceData d) =>
            sink.Publish(Build(KernelEventKind.FileSetSecurity, d.ProcessID, d.ThreadID, d.TimeStamp, d.FileName));
    }

    static KernelEvent Build(KernelEventKind kind, int pid, int tid, DateTime ts, string? path) =>
        new(
            Sequence: 0,           // collector overwrites
            Kind: kind,
            Timestamp: new DateTimeOffset(ts.ToUniversalTime(), TimeSpan.Zero),
            Pid: pid,
            Tid: tid,
            Path: path,
            Target: null,
            Extras: null,
            UserStack: null);
}
