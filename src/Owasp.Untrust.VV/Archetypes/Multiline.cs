#pragma warning disable CS1591

using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>
/// A bounded Unicode string that normalizes CRLF/CR to LF and rejects all other
/// controls except an explicitly permitted tab.
/// </summary>
public abstract class Multiline<TSelf, TDisclosure, TTabPolicy>
    : ValidatedValue<TSelf, string, TDisclosure>
    where TSelf : Multiline<TSelf, TDisclosure, TTabPolicy>, IBoundedStringDefinition
    where TDisclosure : IDisclosurePolicy<string>
    where TTabPolicy : ITabPolicy
{
    protected Multiline(string raw, IFormatProvider? provider = null)
        : base(
            StringValidation.Run<TSelf>(
                raw,
                archetypeNormalization: NormalizeLineEndings,
                archetypeValidation: IsAllowed,
                archetypeCode: "multiline.content",
                archetypeMessage: "The value contains a disallowed control character or invalid Unicode."))
    {
    }

    private static string NormalizeLineEndings(string value) =>
        value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');

    private static bool IsAllowed(string value) =>
        StringValidation.IsWellFormedUnicodeWithoutDisallowedControls(
            value,
            allowLineFeed: true,
            allowTab: TTabPolicy.AllowsTab);
}
