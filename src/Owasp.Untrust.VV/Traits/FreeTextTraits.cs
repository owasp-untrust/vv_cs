using Owasp.Untrust.VV.StringPreprocessing;

namespace Owasp.Untrust.VV.Traits;

public abstract class FreeTextTraits<TSelf, TCharsValidator>
    : StringTraitsFixedArgsNum<
        TSelf, 
        PreprocessingLeaf<TCharsValidator>
        >
    where TSelf : FreeTextTraits<TSelf, TCharsValidator>
        , ILengthBoundsTraits<TSelf>
    where TCharsValidator : struct, ICharactersValidator
{ }
