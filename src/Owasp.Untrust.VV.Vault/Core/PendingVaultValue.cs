using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Sensitivity;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Vault;

/// <summary>Common primitive-input pending state for values that must be stored in a vault.</summary>
public abstract class PendingVaultValue<TSelf, TValue, TReady, TTraits, TArchetype, TDisclosure> :
    PendingValue<TSelf, TValue, TReady, VaultStorageReceipt<TValue>, TTraits, TArchetype, TDisclosure>
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
