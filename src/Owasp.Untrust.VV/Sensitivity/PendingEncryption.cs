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
            RawValueForExplicitRetention,
            envelope ?? throw new InvalidOperationException(
                "The encryption provider returned no encrypted material."));
    }
}
