#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class RetainedTokenizedValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    IExposableValue<TValue>,
    IRetainsPlaintextValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<string>
{
    private readonly TValue _plaintext;

    internal RetainedTokenizedValue(
        TValue plaintext,
        string token)
    {
        _plaintext = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        Token = token ?? throw new ArgumentNullException(nameof(token));
    }

    public string Token { get; }

    public TValue ExposeUnchecked() => _plaintext;

    public string ToPublicString() =>
        PublicRepresentation<string, TDisclosure>.ToPublicString(Token);

    public override string ToString() => ToPublicString();
}
