using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>A cross-validated value that explicitly permits raw-value exposure.</summary>
public abstract class ExposableCrossValidatedValue<TSelf, TValue, TDisclosure>
    : CrossValidatedValue<TSelf, TValue, TDisclosure>, IValidatedValue<TValue>, IExposableValue<TValue>
    where TSelf : ExposableCrossValidatedValue<TSelf, TValue, TDisclosure>
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<TValue>
{
    protected ExposableCrossValidatedValue(CrossValidationCompletion<TValue, TSelf> completion)
        : base(completion)
    {
    }

    public TValue ExposeUnchecked() => GetCrossValidatedValueForDerivedUse();
}
