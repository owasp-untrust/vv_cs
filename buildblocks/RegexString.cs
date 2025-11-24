using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Foundation;

namespace Owasp.Untrust.VV.Build;

public abstract class RegexString<WrapperT> : BoundedString<WrapperT>
   where WrapperT : RegexString<WrapperT>, ICreatable<WrapperT, string>
{
    public required string Pattern { get; init; }

    // Regex options for this wrapper type
    public RegexOptions RegexOptions { get; init; } = RegexOptions.None;
    public TimeSpan Timeout { get; init; } = new TimeSpan(1_000_000); // 100ms
    
    // Shared cache of compiled regexes, keyed by wrapper type
    private static readonly ConcurrentDictionary<Type, Regex> _compiledRegexCache = new();

    private Regex GetRegex()
    {
        var options = RegexOptions;

        // If not compiled, just create a fresh Regex (cheap for occasional use)
        if ((options & RegexOptions.Compiled) == 0)
        {
            return new Regex(Pattern, options, Timeout);
        }

        // Compiled: cache per WrapperT
        var key = typeof(WrapperT);
        return _compiledRegexCache.GetOrAdd(
           key,
           _ => new Regex(Pattern, options, Timeout)
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
}
