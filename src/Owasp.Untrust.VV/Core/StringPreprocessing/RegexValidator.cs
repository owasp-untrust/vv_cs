using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public interface IRegexPattern<TSelf>
    where TSelf : IRegexPattern<TSelf>
{
    static abstract string Pattern { get; }
    static abstract RegexOptions Options { get; }
    static abstract TimeSpan MatchTimeout { get; }
}

public readonly struct RegexValidator<TPattern> : IStringValidator
    where TPattern : IRegexPattern<TPattern>
{
    private static readonly Regex Expression = CreateExpression();

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
            TPattern.Pattern,
            TPattern.Options | RegexOptions.CultureInvariant,
            timeout);
    }
}
