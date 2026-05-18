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
        "351f1bcf0d913233ffeef5ef4da91cd60dbc6455eee9a63093808eee2d10bd64";

    // Future:
    // public const string ExpectedSha256LinuxX64 = "...";
    // public const string ExpectedSha256OsxArm64 = "...";
}
