using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core.StringPreprocessing;

namespace Owasp.Untrust.VV;

/// <summary>A Luhn-valid payment-card number rendered only as a last-four mask.</summary>
public sealed class CreditCard
    : ExposableString<
        CreditCard,
        CreditCard.CreditCardTraits,
        MaskedPii<string, CreditCard.CreditCardMasker>>,
      IValidatedValueWrapperFactory<CreditCard, string>
{
    private CreditCard(string validatedValue)
        : base(validatedValue)
    {
    }

    public static Bounds<int> LengthBounds => CreditCardTraits.LengthBounds;

    public static string Format => "credit-card";

    static CreditCard IValidatedValueWrapperFactory<CreditCard, string>.CreateValidated(
        PostValidationRawValue<string, CreditCard> validated) => new(validated.ValueForReadyConstruction);

    /// <summary>Single-line Unicode and data-annotation validation for payment-card numbers.</summary>
    public sealed class CreditCardTraits :
        StringTraits<
            CreditCardTraits,
            SingleLineUnicode,
            DataAnnotationAttributeValidator<CreditCardAttribute>>,
        ILengthBoundsTraits<CreditCardTraits>
    {
        public static Bounds<int> LengthBounds => new(8, 20);
    }

    /// <summary>Masks every payment-card digit except the final four.</summary>
    public readonly struct CreditCardMasker : IValueMasker<string>
    {
        /// <inheritdoc />
        public static string Mask(string value)
        {
            Span<char> digitsBuffer = stackalloc char[value.Length];
            var digitCount = 0;
            foreach (char character in value)
            {
                if (char.IsAsciiDigit(character))
                {
                    digitsBuffer[digitCount++] = character;
                }
            }

            int visibleCount = Math.Min(4, digitCount);
            int hiddenCount = digitCount - visibleCount;
            return new string('*', hiddenCount) + new string(digitsBuffer.Slice(hiddenCount, visibleCount));
        }
    }
}
