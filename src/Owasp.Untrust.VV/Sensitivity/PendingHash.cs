#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class PendingHash<TValue> : PendingSensitiveValue<TValue>
    where TValue : notnull
{
    public PendingHash(IValidatedValue<TValue> source)
        : base(source)
    {
    }

    public async ValueTask<HashOnlyValue<TValue, TDisclosure>> HashOnlyAsync<TDisclosure>(
        IHashProvider<TValue> provider,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<BinaryArtifact>
    {
        ArgumentNullException.ThrowIfNull(provider);
        cancellationToken.ThrowIfCancellationRequested();

        byte[] hash = await provider
            .HashAsync(ExposeForTransformation(), cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        return new HashOnlyValue<TValue, TDisclosure>(RequireHash(hash));
    }

    public async ValueTask<RetainedHashedValue<TValue, TDisclosure>> HashRetainingPlaintextAsync<TDisclosure>(
        IHashProvider<TValue> provider,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<BinaryArtifact>
    {
        ArgumentNullException.ThrowIfNull(provider);
        cancellationToken.ThrowIfCancellationRequested();

        byte[] hash = await provider
            .HashAsync(ExposeForTransformation(), cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        return new RetainedHashedValue<TValue, TDisclosure>(
            RawValueForExplicitRetention,
            RequireHash(hash));
    }

    private static BinaryArtifact RequireHash(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);

        if (hash.Length == 0)
        {
            throw new InvalidOperationException("The hash provider returned no hash material.");
        }

        return new BinaryArtifact(hash);
    }
}
