using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.StringPreprocessing;

public interface IPreprocessingChain
{
    static abstract string Normalize(string value);

    static abstract ValidationIssue? ValidateCharacters(string value);

    static abstract ValidationIssue? ValidateString(string value);
}
