using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Sensitivity;
using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.Vault;

/// <summary>Base for a value represented by a vault reference and retrieved only at an explicit asynchronous boundary.</summary>
public abstract class VaultStoredValue<TSelf, TValue> : IAsyncExposableValue<TValue>, ITransformedOnlyValue
    where TSelf : VaultStoredValue<TSelf, TValue>, IInternallyTransformedValueFactory<TSelf, VaultStorageReceipt<TValue>>
    where TValue : notnull
{
    private readonly ISecretStore<TValue> _store;
    private readonly SecretReference _reference;
    private readonly string _publicRepresentation;

    protected VaultStoredValue(InternallyTransformedValue<VaultStorageReceipt<TValue>, TSelf> stored)
    {
        ArgumentNullException.ThrowIfNull(stored);
        VaultStorageReceipt<TValue> receipt = stored.ValueForReadyConstruction;
        _store = receipt.Store;
        _reference = receipt.Reference;
        _publicRepresentation = receipt.PublicRepresentation;
    }

    public SecretReference Reference => _reference;

    object? IPubliclyRepresentable.ToPublicValue() => ToPublicString();

    public string ToPublicString() => _publicRepresentation;

    public sealed override string ToString() => ToPublicString();

    public async ValueTask<TValue> ExposeUncheckedAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TValue value = await _store.RetrieveAsync(_reference, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(value);
        return RevalidateRetrievedValue(value);
    }

    protected abstract TValue RevalidateRetrievedValue(TValue value);
}
