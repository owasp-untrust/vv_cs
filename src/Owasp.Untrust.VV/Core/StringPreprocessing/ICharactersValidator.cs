using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public interface ICharactersValidator : IStringPreprocessingStep
{
    ValidationIssue? ValidateCharacters(string value);
}
