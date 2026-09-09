using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Sensitivity;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Vault;

/// <summary>Opaque evidence that a value was stored in a vault and can later be retrieved through its store.</summary>
public sealed class VaultStorageReceipt<TValue>
    where TValue : notnull
{
    internal VaultStorageReceipt(ISecretStore<TValue> store, SecretReference reference, string publicRepresentation)
    {
        Store = store ?? throw new ArgumentNullException(nameof(store));
        Reference = reference ?? throw new ArgumentNullException(nameof(reference));
        PublicRepresentation = publicRepresentation ?? throw new ArgumentNullException(nameof(publicRepresentation));
    }

    public ISecretStore<TValue> Store { get; }

    public SecretReference Reference { get; }

    public string PublicRepresentation { get; }
}

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

/// <summary>Common primitive-input pending state for values that must be stored in a vault.</summary>
public abstract class PendingVaultValue<TSelf, TValue, TReady, TTraits, TArchetype, TDisclosure> :
    PendingFromTraits<TSelf, TValue, TReady, VaultStorageReceipt<TValue>, TTraits, TArchetype, TDisclosure>
    where TSelf : PendingVaultValue<TSelf, TValue, TReady, TTraits, TArchetype, TDisclosure>, IInternallyValidatedValueFactory<TSelf, TValue>
    where TValue : notnull
    where TReady : IInternallyTransformedValueFactory<TReady, VaultStorageReceipt<TValue>>
    where TTraits : IValidationTraits<TValue, TDisclosure>
    where TArchetype : IValidationArchetype<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    protected PendingVaultValue(TValue validatedValue)
        : base(validatedValue)
    {
    }

    public ValueTask<TReady> StoreInVaultAsync(ISecretStore<TValue> store, SecretReference reference, CancellationToken cancellationToken = default) =>
        CompleteAsync(new StoreInVault<TValue>(store, reference, ToPublicString()), cancellationToken);
}

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
