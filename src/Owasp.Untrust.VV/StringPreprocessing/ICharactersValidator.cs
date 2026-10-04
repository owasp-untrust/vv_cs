using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.StringPreprocessing;

public interface ICharactersValidator : IStringPreprocessingStep
{
    ValidationIssue? ValidateCharacters(string value);
}
