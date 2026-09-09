# OWASP Untrust VV Vault

`Owasp.Untrust.VV.Vault` provides the provider-neutral Pending → Ready building blocks for values that must be placed in a vault before they can be used. It depends only on `Owasp.Untrust.VV` and its `ISecretStore<TValue>` abstraction; it does not choose a vault vendor or client library.

`PendingApiKey` is the built-in example. Route or request-body binding parses the primitive directly into `PendingApiKey`. It is locally syntax-validated, renders as `****` plus its final four characters, and does not expose its raw key. `StoreInVaultAsync` writes the key and returns `VaultStoredApiKey` only after storage succeeds. The stored form retains a validated `SecretReference` and has an asynchronous `ExposeUncheckedAsync` boundary that retrieves and revalidates the secret.

```csharp
VaultStoredApiKey stored = await pendingApiKey.StoreInVaultAsync(
    secretStore,
    new SecretReference("users/alice/ai/openai"),
    cancellationToken);

string apiKey = await stored.ExposeUncheckedAsync(cancellationToken);
```

`VaultStoredApiKey.ToString()` and `ToPublicString()` return the masked form, never the API key. `IPubliclyRepresentable.ToPublicValue()` is implemented explicitly and returns the same safe string for integrations such as JSON converters; it is not a usable secret value and is never used for vault storage.

For HashiCorp Vault, implement `ISecretStore<TValue>` in a separate integration package. HashiCorp documents VaultSharp as the C# community client; its generated .NET client is experimental, so this module deliberately does not take a direct HashiCorp dependency. Azure Key Vault likewise has its own official Azure `SecretClient` and belongs in a separate adapter.
