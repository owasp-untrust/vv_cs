#pragma warning disable CS1591

using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>A bounded, well-formed Unicode string with no line breaks or controls.</summary>
public abstract class SingleLine<TSelf, TDisclosure, TTabPolicy>
    : ValidatedValue<TSelf, string, TDisclosure>
    where TSelf : SingleLine<TSelf, TDisclosure, TTabPolicy>, IBoundedStringDefinition
    where TDisclosure : IDisclosurePolicy<string>
    where TTabPolicy : ITabPolicy
{
    protected SingleLine(string raw, IFormatProvider? provider = null)
        : base(
            StringValidation.Run<TSelf>(
                raw,
                archetypeValidation: IsAllowed,
                archetypeCode: "single_line.content",
                archetypeMessage: "The value contains a line break, control character, or invalid Unicode."))
    {
    }

    private static bool IsAllowed(string value) =>
        StringValidation.IsWellFormedUnicodeWithoutDisallowedControls(
            value,
            allowLineFeed: false,
            allowTab: TTabPolicy.AllowsTab);
}
