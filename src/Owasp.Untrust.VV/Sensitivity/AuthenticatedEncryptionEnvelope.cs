#pragma warning disable CS1591
using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Sensitivity;

/// <summary>
/// Immutable output of an authenticated-encryption provider.
/// </summary>
public sealed class AuthenticatedEncryptionEnvelope : IEquatable<AuthenticatedEncryptionEnvelope>
{
    public AuthenticatedEncryptionEnvelope(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> authenticationTag,
        string? keyId = null)
    {
        if (ciphertext.IsEmpty)
        {
            throw new ArgumentException("Ciphertext must not be empty.", nameof(ciphertext));
        }

        if (nonce.IsEmpty)
        {
            throw new ArgumentException("The encryption nonce must not be empty.", nameof(nonce));
        }

        if (authenticationTag.IsEmpty)
        {
            throw new ArgumentException("The authentication tag must not be empty.", nameof(authenticationTag));
        }

        if (keyId is not null && string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentException("A key identifier must not be blank.", nameof(keyId));
        }

        Ciphertext = new BinaryArtifact(ciphertext);
        Nonce = new BinaryArtifact(nonce);
        AuthenticationTag = new BinaryArtifact(authenticationTag);
        KeyId = keyId;
    }

    public BinaryArtifact Ciphertext { get; }

    public BinaryArtifact Nonce { get; }

    public BinaryArtifact AuthenticationTag { get; }

    public string? KeyId { get; }

    public bool Equals(AuthenticatedEncryptionEnvelope? other) =>
        other is not null &&
        Ciphertext.Equals(other.Ciphertext) &&
        Nonce.Equals(other.Nonce) &&
        AuthenticationTag.Equals(other.AuthenticationTag) &&
        string.Equals(KeyId, other.KeyId, StringComparison.Ordinal);

    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is AuthenticatedEncryptionEnvelope other && Equals(other);

    public override int GetHashCode() =>
        HashCode.Combine(Ciphertext, Nonce, AuthenticationTag, KeyId);

    public override string ToString() => "[authenticated ciphertext]";
}
