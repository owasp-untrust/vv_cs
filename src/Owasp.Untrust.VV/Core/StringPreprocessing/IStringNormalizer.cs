namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public interface IStringNormalizer : IStringPreprocessingStep
{
    string NormalizeBeforeValidation(string raw);
}
