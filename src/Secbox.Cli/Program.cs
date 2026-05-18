using Secbox.Core;

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintUsage();
    return 0;
}

switch (args[0])
{
    case "info":
        Console.WriteLine(SecboxApi.GetInfo());
        return 0;

    case "scan":
        if (args.Length < 2) { Console.Error.WriteLine("scan: expected <path>"); return 2; }
        var path = args[1];
        string json;
        if (Directory.Exists(path))
            json = SecboxApi.ScanFolder(path, optionsJson: null);
        else if (File.Exists(path) && path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            json = SecboxApi.ScanSource(path, optionsJson: null);
        else if (File.Exists(path))
            json = SecboxApi.ScanAssembly(path, optionsJson: null);
        else
        {
            Console.Error.WriteLine($"scan: path does not exist: {path}");
            return 2;
        }
        Console.WriteLine(json);
        return 0;

    default:
        Console.Error.WriteLine($"unknown command: {args[0]}");
        PrintUsage();
        return 2;
}

static void PrintUsage()
{
    Console.WriteLine("secbox — security scanner for s&box editor libraries");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  secbox info                 Print build / pack metadata");
    Console.WriteLine("  secbox scan <path>          Scan a folder, .dll, or .cs file");
    Console.WriteLine();
    Console.WriteLine("Output is JSON (ScanReport schema). Pipe to jq / less for readability.");
}
