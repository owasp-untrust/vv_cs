#pragma warning disable CS1591

using System.Numerics;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>A numeric value parsed from text and constrained to inclusive bounds.</summary>
public abstract class BoundedNumber<TSelf, TValue, TDisclosure>
    : ExposableValidatedValue<TSelf, TValue, TDisclosure>
    where TSelf : BoundedNumber<TSelf, TValue, TDisclosure>, IBoundedNumberDefinition<TValue>
    where TValue : notnull, INumber<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    protected BoundedNumber(string raw, IFormatProvider? provider = null)
        : base(Validate(raw, provider))
    {
    }

    private static TValue Validate(string? raw, IFormatProvider? provider)
    {
        var nonNullRaw = ValidationPipeline.RequireRaw(raw);
        ValidationPipeline.Require(
            TValue.TryParse(nonNullRaw, provider, out var parsed),
            "number.parse",
            "The value is not a valid number.");

        var normalized = TSelf.Normalize(parsed!);
        ValidationPipeline.Require(
            TSelf.Bounds.Contains(normalized),
            "number.bounds",
            "The number is outside the allowed range.");
        ValidationPipeline.RequireNoIssue(TSelf.ValidateAdditional(normalized));
        return normalized;
    }
}
