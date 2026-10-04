namespace Owasp.Untrust.VV.Traits;

/// <summary>
/// Documents a reviewed exception for a string value that deliberately cannot use
/// the complete <see cref="StringTraits{TSelf,TFullValidator}"/> processing pipeline.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
public sealed class AllowStringIParsableTraitsAttribute(
    string justification,
    string boundsValidationPerformed,
    string charactersValidationPerformed,
    string normalizationPerformed,
    string stringValidationPerformed) : Attribute
{
    public string Justification { get; } = justification;

    public string BoundsValidationPerformed { get; } = boundsValidationPerformed;

    public string CharactersValidationPerformed { get; } = charactersValidationPerformed;

    public string NormalizationPerformed { get; } = normalizationPerformed;

    public string StringValidationPerformed { get; } = stringValidationPerformed;
}
