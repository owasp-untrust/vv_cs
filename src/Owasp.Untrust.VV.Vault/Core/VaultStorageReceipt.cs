using Owasp.Untrust.VV.Sensitivity;

namespace Owasp.Untrust.VV.Vault;

/// <summary>Opaque evidence that a value was stored in a vault and can later be retrieved through its store.</summary>
public sealed class VaultStorageReceipt<TValue>
    where TValue : notnull
{
    internal VaultStorageReceipt(ISecretStore<TValue> store, VaultPath reference, string publicRepresentation)
    {
        Store = store ?? throw new ArgumentNullException(nameof(store));
        Reference = reference ?? throw new ArgumentNullException(nameof(reference));
        PublicRepresentation = publicRepresentation ?? throw new ArgumentNullException(nameof(publicRepresentation));
    }

    public ISecretStore<TValue> Store { get; }

    public VaultPath Reference { get; }

    public string PublicRepresentation { get; }
}
