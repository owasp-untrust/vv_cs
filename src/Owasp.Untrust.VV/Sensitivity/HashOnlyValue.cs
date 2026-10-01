#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

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

    public string ToPublicString() =>
        PublicRepresentation<BinaryArtifact, TDisclosure>.ToPublicString(_hash);

    public override string ToString() => ToPublicString();
}
