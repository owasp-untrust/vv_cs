using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Sensitivity;

namespace Owasp.Untrust.VV.Vault;

/// <summary>Stores a value in the supplied vault and emits opaque ready-value evidence.</summary>
public sealed class StoreInVault<TValue> : IValueTransformer<TValue, VaultStorageReceipt<TValue>>
    where TValue : notnull
{
    private readonly ISecretStore<TValue> _store;
    private readonly SecretReference _reference;
    private readonly string _publicRepresentation;

    public StoreInVault(ISecretStore<TValue> store, SecretReference reference, string publicRepresentation)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _reference = reference ?? throw new ArgumentNullException(nameof(reference));
        _publicRepresentation = publicRepresentation ?? throw new ArgumentNullException(nameof(publicRepresentation));
    }

    public async ValueTask<VaultStorageReceipt<TValue>> TransformAsync(TValue value, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _store.StoreAsync(_reference, value, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return new VaultStorageReceipt<TValue>(_store, _reference, _publicRepresentation);
    }
}
