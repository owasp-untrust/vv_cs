namespace Owasp.Untrust.VV.StringPreprocessing;

public interface IStringNormalizer : IStringPreprocessingStep
{
    string NormalizeBeforeValidation(string raw);
}
