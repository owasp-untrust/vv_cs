using Owasp.Untrust.VV.Sensitivity;

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
