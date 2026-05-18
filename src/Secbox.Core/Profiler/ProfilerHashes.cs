namespace Secbox.Core.Profiler;

// Pinned SHA-256 of the native profiler binary, per OS/arch. Refused at
// load time if mismatch — same trust model as Secbox.Core itself.
//
// The hash is updated by the release workflow after CMake build; the value
// here is a placeholder until then. Until a real hash is published, the
// adapter ships in `dev mode` (CorePolicy.DevModeActive) which skips
// verification.
public static class ProfilerHashes
{
    public const string ExpectedSha256WinX64 =
        "879f1a6f67c0897a9539040ed24136bfa395707ae92b6a7014ee10c1393de054";

    // Future:
    // public const string ExpectedSha256LinuxX64 = "...";
    // public const string ExpectedSha256OsxArm64 = "...";
}
