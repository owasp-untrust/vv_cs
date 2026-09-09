using Owasp.Untrust.VV.Sensitivity;
using Owasp.Untrust.VV.Vault;
using Owasp.Untrust.VV.Core;
using Xunit;

namespace Owasp.Untrust.VV.Tests;

public sealed class VaultApiKeyTests
{
    [Fact]
    public async Task PendingApiKeyStoresThePrimitiveBeforeCreatingTheVaultBackedReadyValue()
    {
        InMemorySecretStore store = new();
        SecretReference reference = new("users/alice/ai/openai");
        PendingApiKey pending = PendingApiKey.Parse("abcdefghijklmnopqrstuvwxyz123456", null);

        VaultStoredApiKey stored = await pending.StoreInVaultAsync(store, reference);

        Assert.Equal("****3456", pending.ToPublicString());
        Assert.Equal("****3456", stored.ToPublicString());
        Assert.Equal("abcdefghijklmnopqrstuvwxyz123456", await stored.ExposeUncheckedAsync());
        Assert.Equal("abcdefghijklmnopqrstuvwxyz123456", store.StoredSecret);
    }

    [Fact]
    public void PendingApiKeyRejectsAnInvalidPrimitive()
    {
        Assert.Throws<ValidationException>(() => PendingApiKey.Parse("short", null));
    }

    private sealed class InMemorySecretStore : ISecretStore<string>
    {
        public string StoredSecret { get; private set; } = string.Empty;

        public ValueTask StoreAsync(SecretReference reference, string secret, CancellationToken cancellationToken = default)
        {
            StoredSecret = secret;
            return ValueTask.CompletedTask;
        }

        public ValueTask<string> RetrieveAsync(SecretReference reference, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(StoredSecret);
    }
}
