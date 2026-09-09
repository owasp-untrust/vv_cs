#pragma warning disable CS1591

using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>A bounded non-empty string containing only ASCII letters.</summary>
public abstract class SingleWord<TSelf, TDisclosure>
    : ExposableValidatedValue<TSelf, string, TDisclosure>
    where TSelf : SingleWord<TSelf, TDisclosure>, IBoundedStringDefinition
    where TDisclosure : IDisclosurePolicy<string>
{
    protected SingleWord(string raw, IFormatProvider? provider = null)
        : base(
            StringValidation.Run<TSelf>(
                raw,
                archetypeValidation: IsAsciiWord,
                archetypeCode: "single_word.content",
                archetypeMessage: "The value must contain only ASCII letters."))
    {
    }

    public static string Pattern => "^[A-Za-z]+$";

    private static bool IsAsciiWord(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!((character >= 'A' && character <= 'Z') ||
                  (character >= 'a' && character <= 'z')))
            {
                return false;
            }
        }

        return true;
    }
}
