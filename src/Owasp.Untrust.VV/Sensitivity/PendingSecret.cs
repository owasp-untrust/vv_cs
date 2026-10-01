#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class PendingSecret<TValue> : PendingSensitiveValue<TValue>
    where TValue : notnull
{
    public PendingSecret(IValidatedValue<TValue> source)
        : base(source)
    {
    }

    public async ValueTask<StoredValueVaultPath<TValue, TDisclosure>> StoreOnlyAsync<TDisclosure>(
        ISecretStore<TValue> store,
        VaultPath reference,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<VaultPath>
    {
        await StoreAsync(store, reference, cancellationToken).ConfigureAwait(false);
        return new StoredValueVaultPath<TValue, TDisclosure>(reference);
    }

    public async ValueTask<RetainedVaultPathValue<TValue, TDisclosure>> StoreRetainingPlaintextAsync<TDisclosure>(
        ISecretStore<TValue> store,
        VaultPath reference,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<VaultPath>
    {
        await StoreAsync(store, reference, cancellationToken).ConfigureAwait(false);
        return new RetainedVaultPathValue<TValue, TDisclosure>(
            RawValueForExplicitRetention,
            reference);
    }

    private async ValueTask StoreAsync(
        ISecretStore<TValue> store,
        VaultPath reference,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();

        await store
            .StoreAsync(reference, ExposeForTransformation(), cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
    }
}
