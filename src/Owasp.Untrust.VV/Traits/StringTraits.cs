using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.StringPreprocessing;

namespace Owasp.Untrust.VV.Traits;

public abstract class StringTraits<TSelf, TFullValidator>
    : StringTraitsFixedArgsNum<
        TSelf,
        PreprocessingLeaf<TFullValidator>
        >
    where TSelf :
        StringTraits<TSelf, TFullValidator>,
        ILengthBoundsTraits<TSelf>
    where TFullValidator : struct, ICharactersValidator, IStringValidator
{ }

public abstract class StringTraits<TSelf, TStep1, TStep2>
    : StringTraitsFixedArgsNum<
        TSelf, 
        PreprocessingLink<
            TStep2,
            PreprocessingLeaf<TStep1>>
        >
    where TSelf : 
        StringTraits<TSelf, TStep1, TStep2>,
        ILengthBoundsTraits<TSelf>
    where TStep1 : struct, IStringPreprocessingStep /*redundant*/, ICharactersValidator
    where TStep2 : struct, IStringPreprocessingStep
{ }

public abstract class StringTraits<TSelf, TStep1, TStep2, TStep3>
    : StringTraitsFixedArgsNum<
        TSelf, 
        PreprocessingLink<
            TStep3,
            PreprocessingLink<
                TStep2,
                PreprocessingLeaf<TStep1>>>
        >
    where TSelf : 
        StringTraits<TSelf, TStep1, TStep2, TStep3>,
        ILengthBoundsTraits<TSelf>
    where TStep1 : struct, IStringPreprocessingStep /*redundant*/, ICharactersValidator
    where TStep2 : struct, IStringPreprocessingStep
    where TStep3 : struct, IStringPreprocessingStep
{ }

public abstract class StringTraits<TSelf, TStep1, TStep2, TStep3, TStep4>
    : StringTraitsFixedArgsNum<
        TSelf, 
        PreprocessingLink<
            TStep4,
            PreprocessingLink<
                TStep3,
                PreprocessingLink<
                    TStep2,
                    PreprocessingLeaf<TStep1>>>>
        >
    where TSelf : 
        StringTraits<TSelf, TStep1, TStep2, TStep3, TStep4>,
        ILengthBoundsTraits<TSelf>
    where TStep1 : struct, IStringPreprocessingStep /*redundant*/, ICharactersValidator
    where TStep2 : struct, IStringPreprocessingStep
    where TStep3 : struct, IStringPreprocessingStep
    where TStep4 : struct, IStringPreprocessingStep
{ }
