namespace Secbox.Sentinel.Client;

public enum ClientStatus
{
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Degraded,        // connected but partially broken (e.g. pong missed)
    Failed,          // last connect attempt failed terminally
}
