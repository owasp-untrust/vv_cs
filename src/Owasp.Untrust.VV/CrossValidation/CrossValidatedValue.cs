#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>
/// Base for values that may be constructed only from receiver-specific completion
/// evidence created by <see cref="CrossValidationCandidate{TCandidate,TValue,TReceiver,TTraits,TArchetype,TDisclosure}"/>.
/// </summary>
public abstract class CrossValidatedValue<TSelf, TValue, TDisclosure> :
    IValidatedValue<TValue>,
    IValidatedValueStorage<TValue>,
    ICrossValidatedValue
    where TSelf : CrossValidatedValue<TSelf, TValue, TDisclosure>
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<TValue>
{
    private readonly TValue _value;

    protected CrossValidatedValue(CrossValidationCompletion<TValue, TSelf> completion)
    {
        ArgumentNullException.ThrowIfNull(completion);
        _value = completion.ValidatedValue;
    }

    public Type ValueType => typeof(TValue);

    public TValue ExposeUnchecked() => _value;

    TValue IValidatedValueStorage<TValue>.GetRawValueForInternalUse() => _value;

    public object? ToPublicValue() => TDisclosure.ToPublicValue(_value);

    public string ToPublicString() => TDisclosure.ToPublicString(_value);

    public sealed override string ToString() => ToPublicString();
}
