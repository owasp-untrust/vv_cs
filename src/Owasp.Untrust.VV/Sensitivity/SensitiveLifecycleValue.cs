#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

internal static class PublicRepresentation<TValue, TDisclosure>
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<TValue>
{
    internal static object? ToPublicValue(TValue value) =>
        TDisclosure.ToPublicValue(value);

    internal static string ToPublicString(TValue value) =>
        TDisclosure.ToPublicString(value);
}

/// <summary>
/// Base for a pending sensitive transformation. Pending values retain their source
/// by definition and always render as a fixed redacted marker.
/// </summary>
public abstract class PendingSensitiveValue<TValue> : IPubliclyRepresentable
    where TValue : notnull
{
    private readonly IValidatedValue<TValue> _source;
    private readonly IValidatedValueStorage<TValue> _sourceStorage;

    protected PendingSensitiveValue(IValidatedValue<TValue> source)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _sourceStorage = source as IValidatedValueStorage<TValue> ??
            throw new ArgumentException(
                "Sensitive lifecycle operations require a library validated value.",
                nameof(source));
    }

    protected TValue ExposeForTransformation() =>
        _sourceStorage.GetRawValueForInternalUse();

    protected IValidatedValue<TValue> SourceForExplicitRetention => _source;

    public object ToPublicValue() => ToPublicString();

    public string ToPublicString() => "[pending sensitive transformation]";

    public sealed override string ToString() => ToPublicString();
}
