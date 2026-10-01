using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public interface IStringValidator : IStringPreprocessingStep
{
    ValidationIssue? ValidateString(string value);
}
