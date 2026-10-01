using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

/// <summary>Rejects line breaks, controls, and malformed UTF-16 in single-line text.</summary>
public readonly struct SingleLineUnicode : ICharactersValidator
{
    public ValidationIssue? ValidateCharacters(string value)
    {
        return CharacterValidationHelpers.IsWellFormedUnicodeWithoutDisallowedControls(
            value,
            allowLineFeed: false,
            allowTab: false)
            ? null
            : new ValidationIssue(
                "single_line.content",
                "Single-line text must not contain control characters, line breaks, or malformed UTF-16.");
    }
}
