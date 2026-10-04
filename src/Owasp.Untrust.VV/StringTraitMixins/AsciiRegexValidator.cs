using System.Text.RegularExpressions;
using Owasp.Untrust.ValueDescriptors;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.StringPreprocessing;

namespace Owasp.Untrust.VV.StringTraitMixins;

public interface IAsciiRegexPattern<TSelf>
    where TSelf : IAsciiRegexPattern<TSelf>
{
    static abstract RegexAscii Pattern { get; }
    static abstract TimeSpan MatchTimeout { get; }
}

public readonly struct AsciiRegexValidator<TPattern>
    : ICharactersValidator, IStringValidator
    where TPattern : IAsciiRegexPattern<TPattern>
{
    private static readonly Regex Expression = CreateExpression();

    public ValidationIssue? ValidateCharacters(string value)
    {
        // String validator includes characters validation
        // since it only allows ASCII characters, so we can skip the separate check here.
        return null;
    }

    public ValidationIssue? ValidateString(string value)
    {
        try
        {
            return Expression.IsMatch(value)
                ? null
                : new ValidationIssue(
                    "string.pattern",
                    "The string does not match the required pattern.");
        }
        catch (RegexMatchTimeoutException)
        {
            return new ValidationIssue(
                "string.pattern_timeout",
                "The pattern check exceeded its time limit.");
        }
    }

    private static Regex CreateExpression()
    {
        TimeSpan timeout = TPattern.MatchTimeout;
        if (timeout == Regex.InfiniteMatchTimeout || timeout <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("A finite positive regex timeout is required.");
        }

        return new Regex(
            TPattern.Pattern.ExposeUnchecked(),
            TPattern.Pattern.Options,
            timeout);
    }
}
