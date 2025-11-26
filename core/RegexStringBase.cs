using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class RegexStringBase<TWrapper> : BoundedAnyContentStringBase<TWrapper>
   where TWrapper : RegexStringBase<TWrapper>, ICreatable<TWrapper, string>
{
    protected abstract string PatternConstraint();

    // Regex options for this wrapper type
    public RegexOptions RegexOptions { get; init; } = RegexOptions.None;
    public TimeSpan Timeout { get; init; } = new TimeSpan(1_000_000); // 100ms
    
    // Shared cache of compiled regexes, keyed by wrapper type
    private static readonly ConcurrentDictionary<Type, Regex> _compiledRegexCache = new();

    private Regex GetRegex()
    {
        var options = RegexOptions;
        var sharingKey = SharedRegexKey();

        // If not compiled, just create a fresh Regex (cheap for occasional use)
        if ((sharingKey == null) && ((options & RegexOptions.Compiled) == 0))
        {
            return new Regex(PatternConstraint(), options, Timeout);
        }

        // Compiled: cache per TWrapper
        var key = sharingKey ?? typeof(TWrapper);
        return _compiledRegexCache.GetOrAdd(
           key,
           _ => new Regex(PatternConstraint(), options, Timeout)
        );
    }

    protected override ValidationResultHolder ChainableValidation() {
        var result = base.ChainableValidation();
        if (!result.IsValid) {
            return result;
        }
        Debug.Assert(Value != null);

        var regex = GetRegex();
        if (!regex.IsMatch(Value))
        {
            result.Invalidate();
        }

        return result;
    }

    protected virtual RegexOptions ArchetypeOptions() { return RegexOptions.None; }
    protected virtual Type? SharedRegexKey() { return null; }
}
