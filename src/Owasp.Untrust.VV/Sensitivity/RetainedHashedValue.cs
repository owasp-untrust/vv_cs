#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class RetainedHashedValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    IExposableValue<TValue>,
    IRetainsPlaintextValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<BinaryArtifact>
{
    private readonly TValue _plaintext;
    private readonly BinaryArtifact _hash;

    internal RetainedHashedValue(
        TValue plaintext,
        BinaryArtifact hash)
    {
        _plaintext = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        _hash = hash ?? throw new ArgumentNullException(nameof(hash));
    }

    public BinaryArtifact Hash => _hash;

    public TValue ExposeUnchecked() => _plaintext;

    public string ToPublicString() =>
        PublicRepresentation<BinaryArtifact, TDisclosure>.ToPublicString(_hash);

    public override string ToString() => ToPublicString();
}
