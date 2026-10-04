using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Traits;

namespace Owasp.Untrust.VV.Core;

public abstract class ValidatedParsableFromTraits<TSelf, TValue, TTraits, TDisclosure>
    : ValidatedValue<TSelf, TValue, TDisclosure>, IValidatedValue<TValue>, IExposableValue<TValue>, IParsable<TSelf>
    where TSelf : ValidatedParsableFromTraits<TSelf, TValue, TTraits, TDisclosure>, IValidatedValueWrapperFactory<TSelf, TValue>
    where TValue : notnull, IParsable<TValue>
    where TTraits : IParsableTraits<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    protected ValidatedParsableFromTraits(TValue validatedValue) : base(validatedValue) { }

    public TValue ExposeUnchecked() => GetValidatedValueForDerivedUse();

    public static TSelf Parse(string raw, IFormatProvider? provider)
    {
        TValue value = ValidationTraitsPipeline.Run<TValue, TTraits>(raw, provider);
        return TSelf.CreateValidated(new PostValidationRawValue<TValue, TSelf>(value));
    }

    public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out TSelf result)
    {
        if (ValidationTraitsPipeline.TryRun<TValue, TTraits>(raw, provider, out TValue? value))
        {
            result = TSelf.CreateValidated(new PostValidationRawValue<TValue, TSelf>(value));
            return true;
        }

        result = default;
        return false;
    }
}
