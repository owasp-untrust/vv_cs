#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class PendingEncryption<TValue> : PendingSensitiveValue<TValue>
    where TValue : notnull
{
    public PendingEncryption(IValidatedValue<TValue> source)
        : base(source)
    {
    }

    public async ValueTask<EncryptedOnlyValue<TValue, TDisclosure>> EncryptOnlyAsync<TDisclosure>(
        IAuthenticatedEncryptionProvider<TValue> provider,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<AuthenticatedEncryptionEnvelope>
    {
        ArgumentNullException.ThrowIfNull(provider);
        cancellationToken.ThrowIfCancellationRequested();

        AuthenticatedEncryptionEnvelope envelope = await provider
            .EncryptAsync(ExposeForTransformation(), cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        return new EncryptedOnlyValue<TValue, TDisclosure>(
            envelope ?? throw new InvalidOperationException(
                "The encryption provider returned no encrypted material."));
    }

    public async ValueTask<RetainedEncryptedValue<TValue, TDisclosure>> EncryptRetainingPlaintextAsync<TDisclosure>(
        IAuthenticatedEncryptionProvider<TValue> provider,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<AuthenticatedEncryptionEnvelope>
    {
        ArgumentNullException.ThrowIfNull(provider);
        cancellationToken.ThrowIfCancellationRequested();

        AuthenticatedEncryptionEnvelope envelope = await provider
            .EncryptAsync(ExposeForTransformation(), cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        return new RetainedEncryptedValue<TValue, TDisclosure>(
            SourceForExplicitRetention,
            envelope ?? throw new InvalidOperationException(
                "The encryption provider returned no encrypted material."));
    }
}

public sealed class EncryptedOnlyValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    ITransformedOnlyValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<AuthenticatedEncryptionEnvelope>
{
    private readonly AuthenticatedEncryptionEnvelope _envelope;

    internal EncryptedOnlyValue(AuthenticatedEncryptionEnvelope envelope)
    {
        _envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
    }

    public AuthenticatedEncryptionEnvelope Envelope => _envelope;

    public object? ToPublicValue() =>
        PublicRepresentation<AuthenticatedEncryptionEnvelope, TDisclosure>
            .ToPublicValue(_envelope);

    public string ToPublicString() =>
        PublicRepresentation<AuthenticatedEncryptionEnvelope, TDisclosure>
            .ToPublicString(_envelope);

    public override string ToString() => ToPublicString();
}

public sealed class RetainedEncryptedValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    IRetainsPlaintextValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<AuthenticatedEncryptionEnvelope>
{
    private readonly IValidatedValue<TValue> _source;
    private readonly AuthenticatedEncryptionEnvelope _envelope;

    internal RetainedEncryptedValue(
        IValidatedValue<TValue> source,
        AuthenticatedEncryptionEnvelope envelope)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
    }

    public AuthenticatedEncryptionEnvelope Envelope => _envelope;

    public TValue ExposeUnchecked() => _source.ExposeUnchecked();

    public object? ToPublicValue() =>
        PublicRepresentation<AuthenticatedEncryptionEnvelope, TDisclosure>
            .ToPublicValue(_envelope);

    public string ToPublicString() =>
        PublicRepresentation<AuthenticatedEncryptionEnvelope, TDisclosure>
            .ToPublicString(_envelope);

    public override string ToString() => ToPublicString();
}

public static class EncryptionLifecycleExtensions
{
    public static PendingEncryption<TValue> PendingEncryption<TValue>(
        this IValidatedValue<TValue> source)
        where TValue : notnull => new(source);
}
