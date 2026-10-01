using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public readonly struct PreprocessingLink<TStep, TNext> : IPreprocessingChain
    where TStep : struct, IStringPreprocessingStep
    where TNext : struct, IPreprocessingChain
{
    public static string Normalize(string value)
    {
        value = TNext.Normalize(value);
        return PreprocessingDispatch<TStep>.MaybeNormalize(value);
    }

    public static ValidationIssue? ValidateCharacters(string value)
    {
        ValidationIssue? issue =
            PreprocessingDispatch<TStep>.MaybeValidateCharacters(value);

        return issue ?? TNext.ValidateCharacters(value);
    }

    public static ValidationIssue? ValidateString(string value)
    {
        ValidationIssue? issue =
            PreprocessingDispatch<TStep>.MaybeValidateString(value);

        return issue ?? TNext.ValidateString(value);
    }
}
