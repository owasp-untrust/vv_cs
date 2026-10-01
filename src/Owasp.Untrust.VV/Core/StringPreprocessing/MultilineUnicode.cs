using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

/// <summary>Canonicalizes line endings and rejects malformed UTF-16 or disallowed controls.</summary>
public readonly struct MultilineUnicode<TTabPolicy>
    : IStringNormalizer
    , ICharactersValidator
    where TTabPolicy : struct, ITabPolicy   
{
    public string NormalizeBeforeValidation(string raw) =>
        raw.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');

    public ValidationIssue? ValidateCharacters(string value)
    {
        return CharacterValidationHelpers.IsWellFormedUnicodeWithoutDisallowedControls(
            value,
            allowLineFeed: true,
            allowTab: TTabPolicy.AllowsTab)
            ? null
            : new ValidationIssue(
                "multiline.content",
                "Multiline text contains a disallowed control character or malformed UTF-16.");
    }
}
