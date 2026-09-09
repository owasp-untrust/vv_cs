#pragma warning disable CS1591

using System.Globalization;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>A bounded hexadecimal string without a 0x prefix.</summary>
public abstract class HexString<TSelf, TDisclosure>
    : ExposableValidatedValue<TSelf, string, TDisclosure>
    where TSelf : HexString<TSelf, TDisclosure>, IBoundedStringDefinition
    where TDisclosure : IDisclosurePolicy<string>
{
    protected HexString(string raw, IFormatProvider? provider = null)
        : base(
            StringValidation.Run<TSelf>(
                raw,
                archetypeValidation: IsHex,
                archetypeCode: "hex.content",
                archetypeMessage: "The value must contain only hexadecimal digits."))
    {
    }

    public static string Pattern => "^[0-9A-Fa-f]+$";

    public static string Format => "hex";

    public int ToInt32() => int.Parse(ExposeUnchecked(), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);

    public long ToInt64() => long.Parse(ExposeUnchecked(), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);

    public byte[] ToBytes()
    {
        var value = ExposeUnchecked();
        var padded = (value.Length & 1) == 0 ? value : $"0{value}";
        return Convert.FromHexString(padded);
    }

    private static bool IsHex(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }
}
