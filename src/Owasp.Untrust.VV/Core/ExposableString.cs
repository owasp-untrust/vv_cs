using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Traits;

namespace Owasp.Untrust.VV.Core;

public abstract class ExposableString<TSelf, TTraits, TDisclosure>
    : StringValidatedByTraits<TSelf, TTraits, TDisclosure>
    , IValidatedValue<string>
    , IExposableValue<string>
    where TSelf : ExposableString<TSelf, TTraits, TDisclosure>, IValidatedValueWrapperFactory<TSelf, string>
    where TTraits : IStringTraitsAnonymousPreprocessing<TTraits>
    where TDisclosure : IDisclosurePolicy<string>
{
    protected ExposableString(string validatedValue)
        : base(validatedValue)
    {
    }

    public string ExposeUnchecked() => GetValidatedValueForDerivedUse();
}
