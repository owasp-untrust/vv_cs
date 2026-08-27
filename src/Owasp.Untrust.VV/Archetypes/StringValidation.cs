using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

internal static class StringValidation
{
    internal static string Run<TDefinition>(
        string? raw,
        Func<string, string>? archetypeNormalization = null,
        Func<string, bool>? archetypeValidation = null,
        string archetypeCode = "string.invalid_content",
        string archetypeMessage = "The value contains disallowed content.")
        where TDefinition : IBoundedStringDefinition
    {
        var nonNullRaw = ValidationPipeline.RequireRaw(raw);
        var bounds = TDefinition.LengthBounds;

        ValidationPipeline.Require(
            bounds.Contains(nonNullRaw.Length),
            "string.raw_length",
            "The raw string length is outside the allowed range.");

        var archetypeNormalized = archetypeNormalization is null
            ? nonNullRaw
            : archetypeNormalization(nonNullRaw);
        var normalized = TDefinition.Normalize(archetypeNormalized);

        if (normalized is null)
        {
            throw new ValidationException(
                new ValidationIssue(
                    "string.normalization",
                    "String normalization did not produce a value."));
        }
        ValidationPipeline.Require(
            bounds.Contains(normalized.Length),
            "string.length",
            "The normalized string length is outside the allowed range.");

        if (archetypeValidation is not null)
        {
            ValidationPipeline.Require(
                archetypeValidation(normalized),
                archetypeCode,
                archetypeMessage);
        }

        ValidationPipeline.RequireNoIssue(TDefinition.ValidateAdditional(normalized));
        return normalized;
    }

    internal static bool IsWellFormedUnicodeWithoutDisallowedControls(
        string value,
        bool allowLineFeed,
        bool allowTab)
    {
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];

            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                {
                    return false;
                }

                index++;
                continue;
            }

            if (char.IsLowSurrogate(character))
            {
                return false;
            }

            if (char.IsControl(character) &&
                !(allowLineFeed && character == '\n') &&
                !(allowTab && character == '\t'))
            {
                return false;
            }
        }

        return true;
    }
}
