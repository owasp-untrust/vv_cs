using System.Runtime.CompilerServices;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

internal static class PreprocessingDispatch<TStep>
    where TStep : struct, IStringPreprocessingStep
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string MaybeNormalize(string value)
    {
        TStep step = default;

        if (step is IStringNormalizer normalizer)
        {
            return normalizer.NormalizeBeforeValidation(value);
        }

        return value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValidationIssue? MaybeValidateCharacters(string value)
    {
        TStep step = default;

        if (step is ICharactersValidator validator)
        {
            return validator.ValidateCharacters(value);
        }

        return null;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValidationIssue? MaybeValidateString(string value)
    {
        TStep step = default;

        if (step is IStringValidator validator)
        {
            return validator.ValidateString(value);
        }

        return null;
    }
}
