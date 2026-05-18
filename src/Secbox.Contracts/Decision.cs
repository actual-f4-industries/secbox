namespace Secbox.Contracts;

public enum Decision
{
    Unreviewed,
    AllowOnce,
    TrustAlways,
    Block,
    Quarantine,
}
