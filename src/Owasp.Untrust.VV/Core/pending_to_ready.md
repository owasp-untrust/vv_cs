# Pending-to-ready values

Some values are locally valid but must complete a domain action before application code may use their underlying value. Typical actions are checking that an email exists, resolving and authorizing an identifier, hashing a password, encrypting plaintext, storing an API key in a vault, or producing a disclosure token.

The value type produced at the untrusted-input boundary must be the pending type:

```text
route parameter / request body / message field
    → local parsing and validation
    → PendingValue
    → required completion action
    → ready value
```

`PendingValue` is intentionally publicly representable, so diagnostics, logs, and validation errors use its disclosure policy. It deliberately does not implement `IExposableValue<T>`. Its raw locally validated value is held privately and is provided only to `CompleteAsync`. A successful completion creates the ready type using opaque framework evidence (`InternallyTransformedValue<TOutput, TReady>`), whose constructor is internal to this assembly. A consumer cannot construct a ready value merely by calling its public static factory.

## Why pending must begin with the primitive

Do not start with an exposable `ValidatedValue<T>` and subsequently wrap it in `PendingEncryption`, `PendingHash`, or another pending wrapper. That does not enforce the action: the original exposable value still exists and can be retained, logged incorrectly, or passed to code that reads its raw value.

This is insufficient:

```text
primitive → exposable validated value → pending wrapper → encrypted value
```

The required shape is:

```text
primitive → pending value → encrypted value
```

There must be no exposable plaintext value in the second path. The pending type is therefore what route binding, body binding, message deserialization, and other input adapters construct directly. `PendingFromTraits` supplies this shape for locally validated textual input because it implements `IParsable<TSelf>`.

## Completion examples

Cross-validation produces a ready value only after the domain check succeeds:

```csharp
ExistingEmail email = await pendingEmail.CompleteAsync(
    new ConfirmEmailExists(directory),
    cancellationToken);
```

Password hashing produces a ready type that contains hash material rather than plaintext:

```csharp
HashedPassword passwordHash = await pendingPassword.CompleteAsync(
    passwordHasher.HashAsync,
    cancellationToken);
```

The same completion mechanism supports a DI-backed transformer, a lambda, or a delegate method group. The transform input is not exposed to the caller; it is only supplied to the completion operation.

## Ready types

The ready type decides its own capabilities. A cross-validated email may implement `IExposableValidatedValue<string>`. A hashed password, encrypted value, vault reference, or tokenized disclosure normally must not expose the original plaintext at all. If plaintext retention is genuinely required, it must be a separate, explicitly named ready type so callers and reviewers can see that retention occurred.

Rare workflows may return another pending type from a completion operation:

```text
PendingInput → PendingVerifiedInput → ReadyInput
```

The ordinary case remains one required transition from pending input to ready value.
