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
            SourceForExplicitRetention,
            RequireHash(hash));
    }

    private static BinaryArtifact RequireHash(byte[]? hash)
    {
        if (hash is null || hash.Length == 0)
        {
            throw new InvalidOperationException("The hash provider returned no hash material.");
        }

        return new BinaryArtifact(hash);
    }
}

public sealed class HashOnlyValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    ITransformedOnlyValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<BinaryArtifact>
{
    private readonly BinaryArtifact _hash;

    internal HashOnlyValue(BinaryArtifact hash)
    {
        _hash = hash ?? throw new ArgumentNullException(nameof(hash));
    }

    public BinaryArtifact Hash => _hash;

    public object? ToPublicValue() =>
        PublicRepresentation<BinaryArtifact, TDisclosure>.ToPublicValue(_hash);

    public string ToPublicString() =>
        PublicRepresentation<BinaryArtifact, TDisclosure>.ToPublicString(_hash);

    public override string ToString() => ToPublicString();
}

public sealed class RetainedHashedValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    IRetainsPlaintextValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<BinaryArtifact>
{
    private readonly IValidatedValue<TValue> _source;
    private readonly BinaryArtifact _hash;

    internal RetainedHashedValue(
        IValidatedValue<TValue> source,
        BinaryArtifact hash)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _hash = hash ?? throw new ArgumentNullException(nameof(hash));
    }

    public BinaryArtifact Hash => _hash;

    public TValue ExposeUnchecked() => _source.ExposeUnchecked();

    public object? ToPublicValue() =>
        PublicRepresentation<BinaryArtifact, TDisclosure>.ToPublicValue(_hash);

    public string ToPublicString() =>
        PublicRepresentation<BinaryArtifact, TDisclosure>.ToPublicString(_hash);

    public override string ToString() => ToPublicString();
}

public static class HashLifecycleExtensions
{
    public static PendingHash<TValue> PendingHash<TValue>(
        this IValidatedValue<TValue> source)
        where TValue : notnull => new(source);
}
