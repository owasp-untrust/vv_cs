#pragma warning disable CS1591

using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>A bounded Base64 value with an explicit alphabet/padding policy.</summary>
public abstract class Base64<TSelf, TDisclosure, TVariant>
    : ExposableValidatedValue<TSelf, string, TDisclosure>
    where TSelf : Base64<TSelf, TDisclosure, TVariant>, IBoundedStringDefinition
    where TDisclosure : IDisclosurePolicy<string>
    where TVariant : IBase64Variant
{
    protected Base64(string raw, IFormatProvider? provider = null)
        : base(
            StringValidation.Run<TSelf>(
                raw,
                archetypeValidation: TVariant.IsValid,
                archetypeCode: "base64.content",
                archetypeMessage: "The value is not valid Base64 for the selected variant."))
    {
    }

    public static string Format => TVariant.Format;

    public byte[] ToBytes() => TVariant.Decode(ExposeUnchecked());
}
