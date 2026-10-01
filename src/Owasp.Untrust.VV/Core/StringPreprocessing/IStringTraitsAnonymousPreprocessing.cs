namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public interface IStringTraitsAnonymousPreprocessing<TSelf>
    where TSelf :
        IStringTraitsAnonymousPreprocessing<TSelf>
{
    static abstract string NormalizeBeforeValidation(string value);
    static abstract ValidationIssue? ValidateCharacters(string value);
    static abstract ValidationIssue? ValidateString(string value);
    static abstract ValidationIssue? ValidateValue(string raw, out string normalized);
}
