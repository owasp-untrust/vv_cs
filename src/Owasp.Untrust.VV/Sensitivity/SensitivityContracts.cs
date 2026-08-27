#pragma warning disable CS1591
namespace Owasp.Untrust.VV.Sensitivity;

/// <summary>Produces a one-way hash without prescribing an algorithm or key source.</summary>
public interface IHashProvider<in TValue>
{
    ValueTask<byte[]> HashAsync(
        TValue plaintext,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Performs authenticated encryption. Key selection and key management belong to
/// the provider, not to the validated-value object.
/// </summary>
public interface IAuthenticatedEncryptionProvider<in TValue>
{
    ValueTask<AuthenticatedEncryptionEnvelope> EncryptAsync(
        TValue plaintext,
        CancellationToken cancellationToken = default);
}

/// <summary>Replaces a sensitive value with a provider-owned opaque token.</summary>
public interface ITokenizationProvider<in TValue>
{
    ValueTask<string> TokenizeAsync(
        TValue plaintext,
        CancellationToken cancellationToken = default);
}

/// <summary>Stores and retrieves secret material using a validated reference.</summary>
public interface ISecretStore<TValue>
{
    ValueTask StoreAsync(
        SecretReference reference,
        TValue secret,
        CancellationToken cancellationToken = default);

    ValueTask<TValue> RetrieveAsync(
        SecretReference reference,
        CancellationToken cancellationToken = default);
}

/// <summary>Marks a lifecycle value that physically retains no original plaintext.</summary>
public interface ITransformedOnlyValue;

/// <summary>Marks a lifecycle value whose type explicitly announces plaintext retention.</summary>
public interface IRetainsPlaintextValue;
