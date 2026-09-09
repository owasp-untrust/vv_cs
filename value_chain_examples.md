# Value-chain examples

These examples show how application code uses Pending → Ready values. Parsing returns a non-exposable pending state, and only a successful typed transition creates the next state.

Each ready value independently selects its disclosure policy. Disclosure is not a storage policy and is not classified by a fixed enum.

## What `CompleteAsync` returns

Every completion returns `ValueTask<TReady>` to the application. The callback supplied to it returns the information the framework needs to mint that ready type. The callback return type depends on the transition:

| Transition | Callback returns | Framework mints |
| --- | --- | --- |
| Cross-validation | `ValueTask<CrossValidationResult>` | The predetermined ready type, retaining the validated input only after success. |
| Entity authorization | Access facts from one repository query | `AuthorizedEntity<TEntity>` after verifying requested scopes. |
| Password hash | `ValueTask<PasswordHashData>` | `HashedPassword`, replacing plaintext with hash data. |
| Vault storage | `ValueTask<VaultReference>` | `VaultedApiKey`, replacing plaintext with a reference. |
| Encryption | `ValueTask<AuthenticatedEncryptionEnvelope>` | `EncryptedPayload`, replacing plaintext with encrypted material. |
| Token/hash disclosure | `ValueTask<DisclosureToken>` or `ValueTask<DisclosureHash>` | A ready value that retains the operational value but renders the returned disclosure value publicly. |

For transformed values, the framework converts the callback result into opaque `InternallyTransformedValue<TOutput, TReady>` evidence. Its constructor is internal, so a public ready factory cannot be called by application code with fabricated output:

```csharp
public interface IInternallyTransformedValueFactory<TSelf, TOutput>
{
    static abstract TSelf CreateTransformed(
        InternallyTransformedValue<TOutput, TSelf> transformed);
}
```

The framework alone constructs `InternallyTransformedValue<TOutput, TReady>` after the transform succeeds.

## Cross-validation

The candidate and ready value are ordinary domain types. The framework validates the input and creates `IInternallyValidatedValue<T>` evidence; application code cannot create that evidence. A public static factory is therefore safe: callers cannot supply its required argument.

```csharp
public sealed class ExistingEmailCandidate :
    CrossValidationCandidate<
        ExistingEmailCandidate,
        string,
        ExistingEmail,
        EmailTraits,
        BoundedStringArchetype<EmailTraits, RedactedPii<string>>,
        RedactedPii<string>>,
    IInternallyValidatedValueFactory<ExistingEmailCandidate, string>
{
    private ExistingEmailCandidate(IInternallyValidatedValue<string> validated)
        : base(validated) { }

    public static ExistingEmailCandidate CreateValidated(
        IInternallyValidatedValue<string> validated) => new(validated);
}

public sealed class ExistingEmail :
    ExposableCrossValidatedValue<ExistingEmail, string, RedactedPii<string>>,
    ICrossValidatedValueFactory<ExistingEmail, string>
{
    private ExistingEmail(CrossValidationCompletion<string, ExistingEmail> completion)
        : base(completion) { }

    public static ExistingEmail CreateCrossValidated(
        CrossValidationCompletion<string, ExistingEmail> completion) => new(completion);
}
```

`CrossValidationCompletion<string, ExistingEmail>` has an internal constructor. Only the framework can create it after validation succeeds, so an application cannot call `CreateCrossValidated` to bypass cross-validation. Every factory interface follows this pattern: it receives an opaque, framework-created evidence type rather than a raw primitive.

For a one-off check, pass a lambda:

```csharp
ExistingEmail email = await ExistingEmailCandidate.Parse("alice@example.com", null)
    .CompleteAsync(
        async (value, ct) =>
            await directory.ExistsAsync(value, ct)
                ? CrossValidationResult.Success
                : CrossValidationResult.Failure("email.not_found", "The email address is not registered."),
        cancellationToken);
```

For a named delegate method, pass the method group directly:

```csharp
ExistingEmail email = await ExistingEmailCandidate.Parse("alice@example.com", null)
    .CompleteAsync(directory.ConfirmEmailExistsAsync, cancellationToken);
```

Use a functor when the operation is reused or owns dependencies supplied by dependency injection:

```csharp
public sealed class ConfirmEmailExists(IEmailDirectory directory)
    : ICrossValidation<string>
{
    public async ValueTask<CrossValidationResult> ValidateAsync(
        string email,
        CancellationToken cancellationToken = default) =>
        await directory.ExistsAsync(email, cancellationToken)
            ? CrossValidationResult.Success
            : CrossValidationResult.Failure("email.not_found", "The email address is not registered.");
}

builder.Services.AddScoped<ConfirmEmailExists>();

ExistingEmail email = await ExistingEmailCandidate.Parse("alice@example.com", null)
    .CompleteAsync(confirmEmailExists, cancellationToken);
```

The lambda, delegate, and functor overloads have the same enforcement properties. The functor is useful for a reusable, injectable domain operation; it is not a security requirement.

```csharp
ExistingEmailCandidate candidate = ExistingEmailCandidate.Parse(
    "alice@example.com", null);

ExistingEmail email = await candidate.CompleteAsync(
    new ConfirmEmailExists(directory),
    cancellationToken);
```

`candidate` has no `ExposeUnchecked()`. The completion operation is the explicit boundary at which the locally validated email is checked against the directory. Only a successful result mints `ExistingEmail`.

## ID to authorized entity

```csharp
DocumentIdCandidate candidate = DocumentIdCandidate.Parse(documentIdText, null);

AuthorizedEntity<Document> document = await candidate.AuthorizeAsync(
    repository,
    currentSubject,
    new EntityAccessQuery
    {
        RequestedScopes = AuthorizationScopeSet.Of<UpdateDocument>(),
        RequiredRelationships = EntityRelationshipRequirementSet.AnyOf(
            EntityRelationshipRequirement.Owner,
            EntityRelationshipRequirement.SharedEditor),
    },
    authorizationVerifier,
    cancellationToken);

UpdatedDocument updated = await document.ExecuteAsync(
    new UpdateDocumentAction(request),
    cancellationToken);
```

`repository` loads the document together with the ownership proof, relevant relationship proofs, and optional grants in one query. `authorizationVerifier` evaluates those facts against the requested scopes; the repository retrieves facts but does not own authorization policy. `AuthorizedEntity<Document>` has neither an entity property nor `ExposeUnchecked()`. It makes the entity available only to an action after comparing the action's required scopes with the verified granted scopes.

```csharp
public sealed class UpdateDocumentAction(DocumentUpdate request)
    : IEntityAction<UpdateDocumentAction, Document, UpdatedDocument>
{
    public static AuthorizationScopeSet RequiredScopes =>
        AuthorizationScopeSet.Of<UpdateDocument>();

    public ValueTask<UpdatedDocument> ExecuteAsync(
        Document document,
        CancellationToken cancellationToken = default)
    {
        document.Apply(request);
        return ValueTask.FromResult(new UpdatedDocument(document.Id));
    }
}
```

The action is the explicit trusted boundary: it receives the private entity only after the authorization check. The result type should be an operation result or a safe projection, not the raw entity itself.

## Password to password hash

```csharp
PendingPassword password = PendingPassword.Parse(passwordText, null);

HashedPassword passwordHash = await password.CompleteAsync(
    passwordHasher.HashAsync,
    cancellationToken);
```

The callback is a transform, so it returns `ValueTask<PasswordHashData>`, not `CrossValidationResult`:

```csharp
public interface IPasswordHasher
{
    ValueTask<PasswordHashData> HashAsync(
        string plaintext,
        CancellationToken cancellationToken = default);
}

public sealed class HashedPassword :
    IInternallyTransformedValueFactory<HashedPassword, PasswordHashData>
{
    private readonly PasswordHashData _hash;

    private HashedPassword(
        InternallyTransformedValue<PasswordHashData, HashedPassword> transformed) =>
        _hash = transformed.ValueForReadyConstruction;

    public static HashedPassword CreateTransformed(
        InternallyTransformedValue<PasswordHashData, HashedPassword> transformed) =>
        new(transformed);
}
```

`PasswordHashData` is an immutable hash result containing algorithm, work factor, salt, and hash bytes. `HashedPassword` is the new operational value. It retains no plaintext and does not implement `IExposableValue<string>`.

## API key to vault reference

```csharp
PendingApiKey apiKey = PendingApiKey.Parse(apiKeyText, null);

VaultedApiKey vaultedKey = await apiKey.CompleteAsync(
    new StoreApiKeyInVault(vault),
    cancellationToken);
```

`VaultedApiKey` contains a validated vault reference, not the API-key plaintext. It is a storage transition.

The vault callback returns `ValueTask<VaultReference>`. The framework converts that reference into opaque transformed-value evidence and mints `VaultedApiKey`; it does not retain the API key.

## Plaintext to encrypted payload

```csharp
PendingPlaintext plaintext = PendingPlaintext.Parse(plaintextInput, null);

EncryptedPayload encrypted = await plaintext.CompleteAsync(
    new EncryptPayload(encryptor),
    cancellationToken);
```

`EncryptedPayload` retains only the authenticated encryption envelope. It does not expose the original plaintext.

The encryptor callback returns `ValueTask<AuthenticatedEncryptionEnvelope>`. The envelope is the replacement payload used to mint `EncryptedPayload`.

## Tokenized disclosure

```csharp
PendingEmail pendingEmail = PendingEmail.Parse(emailText, null);

TokenizedEmail email = await pendingEmail.CompleteAsync(
    new TokenizeForDisclosure(tokenizer),
    cancellationToken);

string rawForDelivery = email.ExposeUnchecked();
string safeForLogs = email.ToPublicString(); // token
```

Tokenization here is a disclosure transition, not storage. `TokenizedEmail` retains the operational email for delivery, while its disclosure policy renders the provider-issued token.

The tokenizer callback returns `ValueTask<DisclosureToken>`. The framework's disclosure-transformation evidence contains both the retained operational email and the token; the ready factory can use the first for explicit operational exposure and the second only for `ToPublicValue()` and `ToPublicString()`.

## Hashed disclosure

```csharp
PendingCustomerId pendingCustomerId = PendingCustomerId.Parse(customerIdText, null);

HashedDisclosure<CustomerId> customerId = await pendingCustomerId.CompleteAsync(
    new GenerateDisclosureHash(hasher),
    cancellationToken);

CustomerId rawForDomainUse = customerId.ExposeUnchecked();
string safeForLogs = customerId.ToPublicString(); // generated hash
```

This differs from password hashing: the customer ID remains the operational value, while the generated hash is only its public representation.

The hasher callback returns `ValueTask<DisclosureHash>`. The framework retains the customer ID together with the generated disclosure hash; the latter is not a replacement operational value.

## Chaining

Every transition returns its declared next type. When another action is required, that next type is simply another pending value:

```csharp
PendingEmail pendingEmail = PendingEmail.Parse(emailText, null);
ExistingEmail existingEmail = await pendingEmail.CompleteAsync(
    new ConfirmEmailExists(directory), cancellationToken);

EncryptedPayload encrypted = await existingEmail.CompleteAsync(
    new EncryptPayload(encryptor), cancellationToken);
```

The first transition can return a ready exposable value or a further pending state, depending on the domain requirement. No special chaining API is needed.
