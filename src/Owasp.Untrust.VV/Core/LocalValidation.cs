using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core;

/// <summary>Runs the library's complete local validation pipeline for reusable trait definitions.</summary>
public static class LocalValidation
{
    public static TValue ParseAndValidate<TValue, TTraits, TArchetype, TDisclosure>(string raw, IFormatProvider? provider = null)
        where TValue : notnull
        where TTraits : IValidationTraits<TValue, TDisclosure>
        where TArchetype : IValidationArchetype<TValue>
        where TDisclosure : IDisclosurePolicy<TValue> =>
        ValidationTraitsPipeline.Run<TValue, TTraits, TArchetype, TDisclosure>(raw, provider);
}
