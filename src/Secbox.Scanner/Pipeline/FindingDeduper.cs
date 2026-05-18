using Secbox.Contracts;

namespace Secbox.Scanner.Pipeline;

// Collapses duplicate findings produced by multiple finders. Identity is
// (RuleId, Location). Keeps the first occurrence's severity (in practice all
// duplicates share severity since RuleId implies severity).
internal static class FindingDeduper
{
    public static IReadOnlyList<Finding> Dedupe(IEnumerable<Finding> findings)
    {
        var seen = new HashSet<string>();
        var result = new List<Finding>();
        foreach (var f in findings)
        {
            var key = $"{f.RuleId}|{f.Location}";
            if (seen.Add(key)) result.Add(f);
        }
        return result;
    }
}
