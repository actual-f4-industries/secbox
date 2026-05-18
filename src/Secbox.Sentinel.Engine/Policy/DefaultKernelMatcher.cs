using System.Text.RegularExpressions;
using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Policy;

// Default matcher: PID filter + provider filter + glob-style path allowlist.
// All matching is done in-process on the service side so a noisy subscriber
// can't be a DOS vector — events get filtered down to that subscriber's
// interest before being forwarded over the pipe.
public sealed class DefaultKernelMatcher : IKernelRuleMatcher
{
    public MatchResult Match(KernelEvent ev, Subscription sub)
    {
        // PID filter — the most important one.
        if (sub.EditorPid != 0 && ev.Pid != sub.EditorPid) return new(false);

        // Provider filter — translate the event kind to its owning provider.
        var providerForKind = ProviderForKind(ev.Kind);
        if (providerForKind != ProviderKind.None && (sub.Providers & providerForKind) == 0)
            return new(false);

        // Path/target allowlist (optional). If absent, all paths forward.
        if (sub.PathAllowlist is { Count: > 0 })
        {
            var probe = ev.Path ?? ev.Target;
            if (probe == null) return new(false);
            if (!sub.PathAllowlist.Any(g => Glob(g).IsMatch(probe))) return new(false);
        }

        return new(true);
    }

    static ProviderKind ProviderForKind(KernelEventKind k) => k switch
    {
        KernelEventKind.FileCreate or KernelEventKind.FileWrite or KernelEventKind.FileDelete
            or KernelEventKind.FileRename or KernelEventKind.FileSetSecurity => ProviderKind.File,
        KernelEventKind.ProcessStart or KernelEventKind.ProcessStop => ProviderKind.Process,
        KernelEventKind.ImageLoad => ProviderKind.ImageLoad,
        KernelEventKind.NetTcpConnect or KernelEventKind.NetTcpSend or KernelEventKind.NetTcpRecv
            or KernelEventKind.NetUdpSend or KernelEventKind.NetUdpRecv
            or KernelEventKind.NetDnsQuery => ProviderKind.Network,
        KernelEventKind.RegOpenKey or KernelEventKind.RegSetValue
            or KernelEventKind.RegDeleteKey or KernelEventKind.RegDeleteValue => ProviderKind.Registry,
        _ => ProviderKind.None,
    };

    // Cheap glob → regex. ** matches across separators, * matches within a
    // segment, ? matches a single char. Anchors enforced at both ends so an
    // allowlist entry is a full-path match, not a substring.
    static readonly Dictionary<string, Regex> _cache = new(StringComparer.OrdinalIgnoreCase);
    static Regex Glob(string pattern)
    {
        if (_cache.TryGetValue(pattern, out var r)) return r;
        var rx = "^" + Regex.Escape(pattern)
            .Replace(@"\*\*", ".*")
            .Replace(@"\*", "[^/\\\\]*")
            .Replace(@"\?", ".") + "$";
        var compiled = new Regex(rx, RegexOptions.Compiled | RegexOptions.IgnoreCase);
        _cache[pattern] = compiled;
        return compiled;
    }
}
