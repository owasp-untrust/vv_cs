using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core;

/// <summary>
/// A locally validated value that deliberately permits callers to obtain its raw
/// representation. Derive from <see cref="ValidatedValue{TSelf, TValue, TDisclosure}"/>
/// directly when validation must not imply public raw-value exposure.
/// </summary>
public abstract class ExposableValidatedValue<TSelf, TValue, TDisclosure>
    : ValidatedValue<TSelf, TValue, TDisclosure>, IExposableValidatedValue<TValue>
    where TSelf : ExposableValidatedValue<TSelf, TValue, TDisclosure>
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<TValue>
{
    private protected ExposableValidatedValue(TValue validatedValue)
        : base(validatedValue)
    {
    }

    public TValue ExposeUnchecked() => GetValidatedValueForDerivedUse();
}
