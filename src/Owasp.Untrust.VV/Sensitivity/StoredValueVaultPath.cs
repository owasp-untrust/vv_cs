#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class StoredValueVaultPath<TValue, TDisclosure> :
    IPubliclyRepresentable,
    ITransformedOnlyValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<VaultPath>
{
    internal StoredValueVaultPath(VaultPath reference)
    {
        Reference = reference ?? throw new ArgumentNullException(nameof(reference));
    }

    public VaultPath Reference { get; }

    public string ToPublicString() =>
        PublicRepresentation<VaultPath, TDisclosure>.ToPublicString(Reference);

    public override string ToString() => ToPublicString();
}
