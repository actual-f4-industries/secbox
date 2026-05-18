namespace Secbox.Contracts;

public abstract record ScanTarget(string Path);

public sealed record AssemblyTarget(string Path) : ScanTarget(Path);
public sealed record SourceTarget(string Path)   : ScanTarget(Path);
public sealed record FolderTarget(string Path)   : ScanTarget(Path);
