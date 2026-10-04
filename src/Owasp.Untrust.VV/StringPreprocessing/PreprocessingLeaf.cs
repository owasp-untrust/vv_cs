using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.StringPreprocessing;

public readonly struct PreprocessingLeaf<TStep> : IPreprocessingChain
    where TStep : struct, IStringPreprocessingStep, ICharactersValidator
{
    public static string Normalize(string value)
        => PreprocessingDispatch<TStep>.MaybeNormalize(value);

    public static ValidationIssue? ValidateCharacters(string value)
        => PreprocessingDispatch<TStep>.MaybeValidateCharacters(value);

    public static ValidationIssue? ValidateString(string value)
        => PreprocessingDispatch<TStep>.MaybeValidateString(value);
}
