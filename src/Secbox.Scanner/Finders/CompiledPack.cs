using System.Text.RegularExpressions;
using Secbox.Contracts;

namespace Secbox.Scanner.Finders;

// Pre-compiled view of an IRulePack — regexes built once, ready for matching
// against incoming member keys. Finders cache one of these per pack per scan.
internal sealed class CompiledPack
{
    readonly List<(Regex Rx, Rule Rule, bool IsDeny)> _entries = new();

    public string PackId { get; }

    public CompiledPack(IRulePack pack)
    {
        PackId = pack.Info.Id;
        foreach (var rule in pack.Rules)
        {
            var pattern = rule.Pattern.Trim();
            if (string.IsNullOrEmpty(pattern)) continue;

            bool deny = pattern.StartsWith('!');
            if (deny) pattern = pattern[1..];

            // Skip pseudo-patterns used for documentation (NativeBinaryPack).
            if (pattern.Contains(' ') && !pattern.Contains('/')) continue;

            var compiled = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            _entries.Add((new Regex(compiled, RegexOptions.Compiled), rule, deny));
        }
    }

    // Return first matching denylist Rule, or null if no match (or only
    // matches deny-overrides). Used for "is this member flagged?" by finders
    // checking against critical-style rule packs.
    public Rule? Match(string memberKey)
    {
        // Deny-override patterns within a pack mean "this looks like it would
        // match a broader pattern but is explicitly excluded". If any deny
        // pattern matches, we suppress all matches.
        for (int i = 0; i < _entries.Count; i++)
        {
            if (_entries[i].IsDeny && _entries[i].Rx.IsMatch(memberKey))
                return null;
        }

        for (int i = 0; i < _entries.Count; i++)
        {
            if (!_entries[i].IsDeny && _entries[i].Rx.IsMatch(memberKey))
                return _entries[i].Rule;
        }
        return null;
    }
}
