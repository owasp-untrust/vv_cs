#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class PendingSecret<TValue> : PendingSensitiveValue<TValue>
    where TValue : notnull
{
    public PendingSecret(IValidatedValue<TValue> source)
        : base(source)
    {
    }

    public async ValueTask<SecretReferenceOnlyValue<TValue, TDisclosure>> StoreOnlyAsync<TDisclosure>(
        ISecretStore<TValue> store,
        SecretReference reference,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<SecretReference>
    {
        await StoreAsync(store, reference, cancellationToken).ConfigureAwait(false);
        return new SecretReferenceOnlyValue<TValue, TDisclosure>(reference);
    }

    public async ValueTask<RetainedSecretReferenceValue<TValue, TDisclosure>> StoreRetainingPlaintextAsync<TDisclosure>(
        ISecretStore<TValue> store,
        SecretReference reference,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<SecretReference>
    {
        await StoreAsync(store, reference, cancellationToken).ConfigureAwait(false);
        return new RetainedSecretReferenceValue<TValue, TDisclosure>(
            SourceForExplicitRetention,
            reference);
    }

    private async ValueTask StoreAsync(
        ISecretStore<TValue> store,
        SecretReference reference,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();

        await store
            .StoreAsync(reference, ExposeForTransformation(), cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
    }
}

public sealed class SecretReferenceOnlyValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    ITransformedOnlyValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<SecretReference>
{
    internal SecretReferenceOnlyValue(SecretReference reference)
    {
        Reference = reference ?? throw new ArgumentNullException(nameof(reference));
    }

    public SecretReference Reference { get; }

    public object? ToPublicValue() =>
        PublicRepresentation<SecretReference, TDisclosure>.ToPublicValue(Reference);

    public string ToPublicString() =>
        PublicRepresentation<SecretReference, TDisclosure>.ToPublicString(Reference);

    public override string ToString() => ToPublicString();
}

public sealed class RetainedSecretReferenceValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    IRetainsPlaintextValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<SecretReference>
{
    private readonly IValidatedValue<TValue> _source;

    internal RetainedSecretReferenceValue(
        IValidatedValue<TValue> source,
        SecretReference reference)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        Reference = reference ?? throw new ArgumentNullException(nameof(reference));
    }

    public SecretReference Reference { get; }

    public TValue ExposeUnchecked() => _source.ExposeUnchecked();

    public object? ToPublicValue() =>
        PublicRepresentation<SecretReference, TDisclosure>.ToPublicValue(Reference);

    public string ToPublicString() =>
        PublicRepresentation<SecretReference, TDisclosure>.ToPublicString(Reference);

    public override string ToString() => ToPublicString();
}

public static class SecretLifecycleExtensions
{
    public static PendingSecret<TValue> PendingSecret<TValue>(
        this IValidatedValue<TValue> source)
        where TValue : notnull => new(source);
}
