#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core;

/// <summary>
/// Secure storage shared by all locally validated scalar values. External code
/// cannot derive directly from this type because its constructor is restricted
/// to this assembly; public archetypes are the supported extension points.
/// </summary>
public abstract class ValidatedValue<TSelf, TValue, TDisclosure>
    : IValidatedValue<TValue>, IValidatedValueStorage<TValue>
    where TSelf : ValidatedValue<TSelf, TValue, TDisclosure>
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<TValue>
{
    private readonly TValue _value;

    private protected ValidatedValue(TValue validatedValue)
    {
        _value = validatedValue ?? throw new ArgumentNullException(nameof(validatedValue));
    }

    public Type ValueType => typeof(TValue);

    public TValue ExposeUnchecked() => _value;

    TValue IValidatedValueStorage<TValue>.GetRawValueForInternalUse() => _value;

    public object? ToPublicValue() => TDisclosure.ToPublicValue(_value);

    public string ToPublicString() => TDisclosure.ToPublicString(_value);

    public sealed override string ToString() => ToPublicString();

    /// <summary>Implements the non-throwing half of a leaf's IParsable contract.</summary>
    protected static bool TryParseCore(
        string? raw,
        IFormatProvider? provider,
        Func<string, IFormatProvider?, TSelf> factory,
        [MaybeNullWhen(false)] out TSelf result)
    {
        ArgumentNullException.ThrowIfNull(factory);

        if (raw is null)
        {
            result = default;
            return false;
        }

        try
        {
            result = factory(raw, provider);
            return true;
        }
        catch (ValidationException)
        {
            result = default;
            return false;
        }
    }
}
