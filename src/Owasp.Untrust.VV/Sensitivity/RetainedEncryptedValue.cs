#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class RetainedEncryptedValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    IExposableValue<TValue>,
    IRetainsPlaintextValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<AuthenticatedEncryptionEnvelope>
{
    private readonly TValue _plaintext;
    private readonly AuthenticatedEncryptionEnvelope _envelope;

    internal RetainedEncryptedValue(
        TValue plaintext,
        AuthenticatedEncryptionEnvelope envelope)
    {
        _plaintext = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        _envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
    }

    public AuthenticatedEncryptionEnvelope Envelope => _envelope;

    public TValue ExposeUnchecked() => _plaintext;

    public string ToPublicString() =>
        PublicRepresentation<AuthenticatedEncryptionEnvelope, TDisclosure>
            .ToPublicString(_envelope);

    public override string ToString() => ToPublicString();
}
