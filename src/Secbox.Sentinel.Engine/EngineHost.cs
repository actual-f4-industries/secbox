using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Secbox.Sentinel.Engine.Collection;
using Secbox.Sentinel.Engine.Policy;

namespace Secbox.Sentinel.Engine;

// Convenience composition root. The Service project (or unit tests) gets a
// fully-wired collector + matcher + registry without rewiring boilerplate.
// Keeps the project's surface area narrow: callers depend on EngineHost,
// not on individual Collection/Policy classes.
public sealed class EngineHost : IAsyncDisposable
{
    public EtwCollector Collector { get; }
    public IKernelRuleMatcher Matcher { get; }
    public SubscriptionRegistry Subscriptions { get; }
    public ProcessTree ProcessTree { get; }

    public EngineHost(ILoggerFactory? loggers = null)
    {
        loggers ??= NullLoggerFactory.Instance;
        Collector = new EtwCollector(loggers.CreateLogger<EtwCollector>());
        ProcessTree = new ProcessTree();
        Matcher = new DefaultKernelMatcher(ProcessTree);
        Subscriptions = new SubscriptionRegistry(ProcessTree);
    }

    // Default provider lineup. The service host calls this once at startup.
    // Individual providers can be left out by callers that need a leaner
    // session (smaller buffers, fewer keywords).
    public void RegisterDefaultProviders()
    {
        Collector.AddProvider(new FileProvider());
        Collector.AddProvider(new ProcessProvider());
        Collector.AddProvider(new NetworkProvider());
        Collector.AddProvider(new RegistryProvider());
        Collector.AddProvider(new ImageLoadProvider());
    }

    public Task StartAsync(CancellationToken ct) => Collector.StartAsync(ct);

    public ValueTask DisposeAsync() => Collector.DisposeAsync();
}
