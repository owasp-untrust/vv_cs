using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public readonly struct MultilineAscii<TTabPolicy>
    : IStringNormalizer
    , ICharactersValidator
    where TTabPolicy : struct, ITabPolicy
{
    public string NormalizeBeforeValidation(string raw)
    {
        return raw
            .Replace("\r\n", "\n")
            .Replace('\r', '\n');
    }

    public ValidationIssue? ValidateCharacters(string value)
    {
        foreach (char c in value)
        {
            if (c == '\n' || (TTabPolicy.AllowsTab && c == '\t'))
            {
                continue;
            }

            if (c < 0x20 || c > 0x7E)
            {
                return new ValidationIssue(
                    "string.ascii_character",
                    $"Character U+{(int)c:X4} is not permitted.");
            }
        }

        return null;
    }
}
