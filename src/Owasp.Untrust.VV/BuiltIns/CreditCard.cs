using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV;

/// <summary>A Luhn-valid payment-card number rendered only as a last-four mask.</summary>
public sealed class CreditCard
    : BoundedString<CreditCard, MaskedPii<string, CreditCardMasker>>,
      IBoundedStringDefinition,
      IParsable<CreditCard>
{
    private static readonly CreditCardAttribute Validator = new();

    private CreditCard(string raw, IFormatProvider? provider)
        : base(raw, provider)
    {
    }

    /// <inheritdoc />
    public static Bounds<int> LengthBounds => new(8, 20);

    /// <inheritdoc />
    public static string? Format => "credit-card";

    /// <inheritdoc />
    public static ValidationIssue? ValidateAdditional(string normalized) =>
        Validator.IsValid(normalized)
            ? null
            : new ValidationIssue("credit_card.format", "The value is not a valid payment-card number.");

    /// <inheritdoc />
    public static CreditCard Parse(string raw, IFormatProvider? provider) => new(raw, provider);

    /// <inheritdoc />
    public static bool TryParse(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out CreditCard result) =>
        TryParseCore(raw, provider, static (value, format) => new CreditCard(value, format), out result);
}

/// <summary>Masks every payment-card digit except the final four.</summary>
public readonly struct CreditCardMasker : IValueMasker<string>
{
    /// <inheritdoc />
    public static string Mask(string value)
    {
        Span<char> digitsBuffer = stackalloc char[value.Length];
        var digitCount = 0;
        foreach (var character in value)
        {
            if (char.IsAsciiDigit(character))
            {
                digitsBuffer[digitCount++] = character;
            }
        }

        var visibleCount = Math.Min(4, digitCount);
        var hiddenCount = digitCount - visibleCount;
        return new string('*', hiddenCount) + new string(digitsBuffer.Slice(hiddenCount, visibleCount));
    }
}
