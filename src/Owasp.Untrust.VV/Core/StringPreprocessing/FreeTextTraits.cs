namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public abstract class FreeTextTraits<TSelf, TCharsValidator>
    : StringTraitsFixedArgsNum<
        TSelf, 
        PreprocessingLeaf<TCharsValidator>
        >
    where TSelf : 
        FreeTextTraits<TSelf, TCharsValidator>,
        ILengthBoundsTraits<TSelf>
    where TCharsValidator : struct, ICharactersValidator
{ }
