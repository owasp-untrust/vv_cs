#pragma warning disable CS1591
using Xunit;
using System.Reflection;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Sensitivity;

namespace Owasp.Untrust.VV.Tests;

public sealed class SensitivityLifecycleTests
{
    [Fact]
    public async Task HashOnlyDoesNotRetainPlaintextAndCopiesProviderBuffers()
    {
        Email email = Email.Parse("alice@example.com", null);
        byte[] providerBuffer = [1, 2, 3, 4];
        RecordingHasher hasher = new(providerBuffer);

        HashOnlyValue<string, HexDisclosure> hashOnly = await email
            .PendingHash()
            .HashOnlyAsync<HexDisclosure>(hasher);

        providerBuffer[0] = 99;
        byte[] exposedCopy = hashOnly.Hash.ExposeUnchecked();
        exposedCopy[1] = 88;

        Assert.Equal("alice@example.com", hasher.LastPlaintext);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, hashOnly.Hash.ExposeUnchecked());
        Assert.Equal("01020304", hashOnly.ToString());
        Assert.IsAssignableFrom<ITransformedOnlyValue>(hashOnly);
        AssertNoPlaintextStorage(hashOnly.GetType());
        Assert.Null(hashOnly.GetType().GetMethod("ExposeUnchecked"));
    }

    [Fact]
    public async Task RetainedHashExplicitlyAnnouncesAndExposesPlaintext()
    {
        Email email = Email.Parse("alice@example.com", null);

        RetainedHashedValue<string, HexDisclosure> retained = await email
            .PendingHash()
            .HashRetainingPlaintextAsync<HexDisclosure>(new RecordingHasher([7, 8]));

        Assert.IsAssignableFrom<IRetainsPlaintextValue>(retained);
        Assert.Equal("alice@example.com", retained.ExposeUnchecked());
        Assert.Equal("0708", retained.ToPublicString());
    }

    [Fact]
    public async Task EncryptionOnlyRetainsOnlyDefensivelyCopiedEnvelope()
    {
        Email email = Email.Parse("alice@example.com", null);
        byte[] ciphertext = [10, 11];
        byte[] nonce = [12];
        byte[] tag = [13];
        RecordingEncryptor encryptor = new(ciphertext, nonce, tag);

        EncryptedOnlyValue<string, RedactedSecret<AuthenticatedEncryptionEnvelope>> encrypted =
            await email.PendingEncryption()
                .EncryptOnlyAsync<RedactedSecret<AuthenticatedEncryptionEnvelope>>(encryptor);

        ciphertext[0] = 0;
        nonce[0] = 0;
        tag[0] = 0;

        Assert.Equal(new byte[] { 10, 11 }, encrypted.Envelope.Ciphertext.ExposeUnchecked());
        Assert.Equal(new byte[] { 12 }, encrypted.Envelope.Nonce.ExposeUnchecked());
        Assert.Equal(new byte[] { 13 }, encrypted.Envelope.AuthenticationTag.ExposeUnchecked());
        Assert.Equal("[sensitive]", encrypted.ToString());
        AssertNoPlaintextStorage(encrypted.GetType());
        Assert.Null(encrypted.GetType().GetMethod("ExposeUnchecked"));
    }

    [Fact]
    public async Task TokenAndSecretReferenceOnlyStatesDoNotRetainSource()
    {
        Email email = Email.Parse("alice@example.com", null);
        InMemorySecretStore store = new();
        SecretReference reference = new("users/alice/api-key");

        TokenOnlyValue<string, RedactedPii<string>> tokenOnly = await email
            .PendingTokenization()
            .TokenizeOnlyAsync<RedactedPii<string>>(new FixedTokenizer("tok_123"));
        SecretReferenceOnlyValue<string, RedactedSecret<SecretReference>> secretOnly =
            await email.PendingSecret()
                .StoreOnlyAsync<RedactedSecret<SecretReference>>(store, reference);

        Assert.Equal("tok_123", tokenOnly.Token);
        Assert.Equal("[sensitive]", tokenOnly.ToString());
        Assert.Equal("alice@example.com", store.StoredSecret);
        Assert.Same(reference, secretOnly.Reference);
        AssertNoPlaintextStorage(tokenOnly.GetType());
        AssertNoPlaintextStorage(secretOnly.GetType());
        Assert.Null(secretOnly.GetType().GetMethod("ExposeUnchecked"));
    }

    [Fact]
    public async Task ProvidersReceiveCancellationAndCancelledWorkProducesNoState()
    {
        Email email = Email.Parse("alice@example.com", null);
        CancellationTokenSource source = new();
        source.Cancel();
        RecordingHasher hasher = new([1]);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await email.PendingHash().HashOnlyAsync<HexDisclosure>(hasher, source.Token));

        Assert.False(hasher.WasCalled);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("/absolute/key")]
    [InlineData("C:\\absolute\\key")]
    [InlineData("users/../key")]
    [InlineData("users//key")]
    public void SecretReferencesRejectUnboundedPaths(string path)
    {
        Assert.ThrowsAny<ArgumentException>(() => new SecretReference(path));
    }

    private static void AssertNoPlaintextStorage(Type transformedType)
    {
        FieldInfo[] fields = transformedType.GetFields(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        Assert.DoesNotContain(fields, static field =>
            typeof(IValidatedValue<string>).IsAssignableFrom(field.FieldType));
        Assert.DoesNotContain(fields, static field =>
            field.Name.Contains("source", StringComparison.OrdinalIgnoreCase) ||
            field.Name.Contains("plaintext", StringComparison.OrdinalIgnoreCase));
    }

    private readonly struct HexDisclosure : IDisclosurePolicy<BinaryArtifact>
    {
        public static object ToPublicValue(BinaryArtifact value) => value.ToHexString();

        public static string ToPublicString(BinaryArtifact value) => value.ToHexString();
    }

    private sealed class RecordingHasher(byte[] output) : IHashProvider<string>
    {
        public bool WasCalled { get; private set; }

        public string? LastPlaintext { get; private set; }

        public ValueTask<byte[]> HashAsync(
            string plaintext,
            CancellationToken cancellationToken = default)
        {
            WasCalled = true;
            LastPlaintext = plaintext;
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(output);
        }
    }

    private sealed class RecordingEncryptor(
        byte[] ciphertext,
        byte[] nonce,
        byte[] tag) : IAuthenticatedEncryptionProvider<string>
    {
        public ValueTask<AuthenticatedEncryptionEnvelope> EncryptAsync(
            string plaintext,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                new AuthenticatedEncryptionEnvelope(ciphertext, nonce, tag, "test-key"));
        }
    }

    private sealed class FixedTokenizer(string token) : ITokenizationProvider<string>
    {
        public ValueTask<string> TokenizeAsync(
            string plaintext,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(token);
        }
    }

    private sealed class InMemorySecretStore : ISecretStore<string>
    {
        public string? StoredSecret { get; private set; }

        public ValueTask StoreAsync(
            SecretReference reference,
            string secret,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StoredSecret = secret;
            return ValueTask.CompletedTask;
        }

        public ValueTask<string> RetrieveAsync(
            SecretReference reference,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(StoredSecret ?? throw new InvalidOperationException());
        }
    }
}
