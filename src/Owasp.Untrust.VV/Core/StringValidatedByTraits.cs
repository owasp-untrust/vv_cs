using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Traits;

namespace Owasp.Untrust.VV.Core;

public abstract class StringValidatedByTraits<TSelf, TTraits, TDisclosure>
    : ValidatedValue<TSelf, string, TDisclosure>, IParsable<TSelf>
    where TSelf : StringValidatedByTraits<TSelf, TTraits, TDisclosure>
        , IValidatedValueWrapperFactory<TSelf, string>
    where TTraits : IStringTraitsAnonymousPreprocessing<TTraits>
    where TDisclosure : IDisclosurePolicy<string>
{
    protected StringValidatedByTraits(string validatedValue)
        : base(validatedValue)
    {
    }

    public static TSelf Parse(string raw, IFormatProvider? provider)
    {
        ValidationTests.RequireNoIssue(TTraits.ValidateValue(raw, out string normalized));
        return TSelf.CreateValidated(new PostValidationRawValue<string, TSelf>(normalized));
    }

    public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out TSelf result)
    {
        if (raw is null || TTraits.ValidateValue(raw, out string normalized) is not null)
        {
            result = default;
            return false;
        }

        result = TSelf.CreateValidated(new PostValidationRawValue<string, TSelf>(normalized));
        return true;
    }
}
