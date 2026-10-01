using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core;

/// <summary>Runs the library's complete local validation pipeline for reusable trait definitions.</summary>
public static class LocalValidation
{
    public static TValue ParseAndValidate<TValue, TTraits>(string raw, IFormatProvider? provider = null)
        where TValue : notnull, IParsable<TValue>
        where TTraits : IParsableTraits<TValue> =>
        ValidationTraitsPipeline.Run<TValue, TTraits>(raw, provider);
}
