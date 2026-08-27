#pragma warning disable CS1591

using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>A string with mandatory raw and normalized length bounds.</summary>
public abstract class BoundedString<TSelf, TDisclosure>
    : ValidatedValue<TSelf, string, TDisclosure>
    where TSelf : BoundedString<TSelf, TDisclosure>, IBoundedStringDefinition
    where TDisclosure : IDisclosurePolicy<string>
{
    protected BoundedString(string raw, IFormatProvider? provider = null)
        : base(StringValidation.Run<TSelf>(raw))
    {
    }
}
