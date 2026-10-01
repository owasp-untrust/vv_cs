#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class RetainedVaultPathValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    IExposableValue<TValue>,
    IRetainsPlaintextValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<VaultPath>
{
    private readonly TValue _plaintext;

    internal RetainedVaultPathValue(
        TValue plaintext,
        VaultPath reference)
    {
        _plaintext = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        Reference = reference ?? throw new ArgumentNullException(nameof(reference));
    }

    public VaultPath Reference { get; }

    public TValue ExposeUnchecked() => _plaintext;

    public string ToPublicString() =>
        PublicRepresentation<VaultPath, TDisclosure>.ToPublicString(Reference);

    public override string ToString() => ToPublicString();
}
