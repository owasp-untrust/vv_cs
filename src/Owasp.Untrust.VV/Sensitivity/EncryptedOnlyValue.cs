#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class EncryptedOnlyValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    ITransformedOnlyValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<AuthenticatedEncryptionEnvelope>
{
    private readonly AuthenticatedEncryptionEnvelope _envelope;

    internal EncryptedOnlyValue(AuthenticatedEncryptionEnvelope envelope)
    {
        _envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
    }

    public AuthenticatedEncryptionEnvelope Envelope => _envelope;

    public string ToPublicString() =>
        PublicRepresentation<AuthenticatedEncryptionEnvelope, TDisclosure>
            .ToPublicString(_envelope);

    public override string ToString() => ToPublicString();
}
