using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Collection;

public sealed class NetworkProvider : IKernelProvider
{
    public ProviderKind Kind => ProviderKind.Network;

    public KernelTraceEventParser.Keywords Keywords =>
        KernelTraceEventParser.Keywords.NetworkTCPIP;

    public void Subscribe(KernelTraceEventParser parser, IKernelEventSink sink)
    {
        parser.TcpIpConnect += (TcpIpConnectTraceData d) =>
            sink.Publish(Build(KernelEventKind.NetTcpConnect, d.ProcessID, d.ThreadID, d.TimeStamp,
                target: $"{d.daddr}:{d.dport}"));

        parser.TcpIpSend += (TcpIpSendTraceData d) =>
            sink.Publish(Build(KernelEventKind.NetTcpSend, d.ProcessID, d.ThreadID, d.TimeStamp,
                target: $"{d.daddr}:{d.dport}", extras: new() { ["bytes"] = d.size.ToString() }));

        parser.TcpIpRecv += (TcpIpTraceData d) =>
            sink.Publish(Build(KernelEventKind.NetTcpRecv, d.ProcessID, d.ThreadID, d.TimeStamp,
                target: $"{d.saddr}:{d.sport}", extras: new() { ["bytes"] = d.size.ToString() }));

        parser.UdpIpSend += (UdpIpTraceData d) =>
            sink.Publish(Build(KernelEventKind.NetUdpSend, d.ProcessID, d.ThreadID, d.TimeStamp,
                target: $"{d.daddr}:{d.dport}"));

        parser.UdpIpRecv += (UdpIpTraceData d) =>
            sink.Publish(Build(KernelEventKind.NetUdpRecv, d.ProcessID, d.ThreadID, d.TimeStamp,
                target: $"{d.saddr}:{d.sport}"));
    }

    static KernelEvent Build(
        KernelEventKind kind,
        int pid, int tid, DateTime ts,
        string target,
        Dictionary<string, string>? extras = null) =>
        new(
            Sequence: 0,
            Kind: kind,
            Timestamp: new DateTimeOffset(ts.ToUniversalTime(), TimeSpan.Zero),
            Pid: pid,
            Tid: tid,
            Path: null,
            Target: target,
            Extras: extras,
            UserStack: null);
}
