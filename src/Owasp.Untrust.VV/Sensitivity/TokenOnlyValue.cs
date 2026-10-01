#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class TokenOnlyValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    ITransformedOnlyValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<string>
{
    internal TokenOnlyValue(string token)
    {
        Token = token ?? throw new ArgumentNullException(nameof(token));
    }

    public string Token { get; }

    public string ToPublicString() =>
        PublicRepresentation<string, TDisclosure>.ToPublicString(Token);

    public override string ToString() => ToPublicString();
}
