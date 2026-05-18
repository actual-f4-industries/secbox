using Secbox.Sentinel.Contracts;

namespace Secbox.Sentinel.Engine.Policy;

// Filter applied per-subscription: decides whether an event matches the
// subscription's interest profile (PID, providers, path allowlist) and
// optionally annotates it with a severity hint.
//
// Pulled out behind an interface so we can swap the default glob/PID
// matcher for a more sophisticated policy engine later (CEL, OPA, learned)
// without touching SubscriptionRegistry or PipeServer.
public interface IKernelRuleMatcher
{
    MatchResult Match(KernelEvent ev, Subscription subscription);
}

public readonly record struct MatchResult(bool Forward, MatchTag Tag = MatchTag.None);

public enum MatchTag
{
    None,
    Suspect,           // forward + mark suspicious
    BeyondProjectRoot, // forward + flag as outside project scope
}
