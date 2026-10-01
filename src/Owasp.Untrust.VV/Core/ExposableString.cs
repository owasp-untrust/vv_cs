using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core.StringPreprocessing;

namespace Owasp.Untrust.VV.Core;

public abstract class ExposableString<TSelf, TTraits, TDisclosure>
    : StringValidatedByTraits<TSelf, TTraits, TDisclosure>
    , IExposableValidatedValue<string>
    where TSelf : ExposableString<TSelf, TTraits, TDisclosure>, IValidatedValueWrapperFactory<TSelf, string>
    where TTraits : IStringTraitsAnonymousPreprocessing<TTraits>
    where TDisclosure : IDisclosurePolicy<string>
{
    private protected ExposableString(string validatedValue)
        : base(validatedValue)
    {
    }

    public string ExposeUnchecked() => GetValidatedValueForDerivedUse();
}
