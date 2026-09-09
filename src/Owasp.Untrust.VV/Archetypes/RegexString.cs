#pragma warning disable CS1591

using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>A bounded string that must match a fixed regular expression.</summary>
public abstract class RegexString<TSelf, TDisclosure>
    : ExposableValidatedValue<TSelf, string, TDisclosure>
    where TSelf : RegexString<TSelf, TDisclosure>, IRegexStringDefinition
    where TDisclosure : IDisclosurePolicy<string>
{
    private static readonly Regex Expression = CreateExpression();

    protected RegexString(string raw, IFormatProvider? provider = null)
        : base(
            StringValidation.Run<TSelf>(
                raw,
                archetypeValidation: Matches,
                archetypeCode: "string.pattern",
                archetypeMessage: "The string does not match the required pattern."))
    {
    }

    private static Regex CreateExpression()
    {
        var timeout = TSelf.MatchTimeout;
        if (timeout == Regex.InfiniteMatchTimeout || timeout <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("A finite positive regex timeout is required.");
        }

        return new Regex(
            TSelf.Pattern,
            TSelf.Options | RegexOptions.CultureInvariant,
            timeout);
    }

    private static bool Matches(string value)
    {
        try
        {
            return Expression.IsMatch(value);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}
