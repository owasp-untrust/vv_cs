using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Traits;
using Owasp.Untrust.VV.Sensitivity;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Vault;

/// <summary>Common primitive-input pending state for values that must be stored in a vault.</summary>
public abstract class PendingVaultString<TSelf, TNext, TTraits> :
    PendingString<TSelf, TNext, VaultStorageReceipt<string>, TTraits>
    where TSelf : PendingVaultString<TSelf, TNext, TTraits>
        , IValidatedValueWrapperFactory<TSelf, string>
    where TNext : IInternallyTransformedValueFactory<TNext, VaultStorageReceipt<string>>
    where TTraits : IStringTraitsAnonymousPreprocessing<TTraits>
{
    protected PendingVaultString(string validatedValue)
        : base(validatedValue)
    {
    }

    public ValueTask<TNext> StoreInVaultAsync(ISecretStore<string> store, VaultPath reference, CancellationToken cancellationToken = default) =>
        CompleteAsync(new StoreInVault<string>(store, reference, ToPublicString()), cancellationToken);
}
