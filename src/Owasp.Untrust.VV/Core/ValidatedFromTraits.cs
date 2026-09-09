using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core;

/// <summary>Library-only construction hook implemented explicitly by a leaf.</summary>
public interface IValidatedValueFactory<TSelf, TValue>
    where TValue : notnull
{
    static abstract TSelf CreateValidated(InternallyValidatedValue<TValue, TSelf> validated);
}

/// <summary>A validated value whose complete local pipeline is supplied by reusable traits.</summary>
public abstract class ValidatedFromTraits<TSelf, TValue, TTraits, TArchetype, TDisclosure>
    : ExposableValidatedValue<TSelf, TValue, TDisclosure>, IParsable<TSelf>
    where TSelf : ValidatedFromTraits<TSelf, TValue, TTraits, TArchetype, TDisclosure>,
        IValidatedValueFactory<TSelf, TValue>
    where TValue : notnull
    where TTraits : IValidationTraits<TValue, TDisclosure>
    where TArchetype : IValidationArchetype<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    protected ValidatedFromTraits(TValue validatedValue)
        : base(validatedValue)
    {
    }

    public static TSelf Parse(string raw, IFormatProvider? provider)
    {
        TValue validated = ValidationTraitsPipeline.Run<TValue, TTraits, TArchetype, TDisclosure>(raw, provider);
        return TSelf.CreateValidated(new InternallyValidatedValue<TValue, TSelf>(validated));
    }

    public static bool TryParse(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out TSelf result)
    {
        if (ValidationTraitsPipeline.TryRun<TValue, TTraits, TArchetype, TDisclosure>(
                raw,
                provider,
                out TValue? validated))
        {
            result = TSelf.CreateValidated(new InternallyValidatedValue<TValue, TSelf>(validated));
            return true;
        }

        result = default;
        return false;
    }
}

/// <summary>Convenience base for string-valued traits.</summary>
public abstract class ValidatedStringFromTraits<TSelf, TTraits, TArchetype, TDisclosure>
    : ValidatedFromTraits<TSelf, string, TTraits, TArchetype, TDisclosure>
    where TSelf : ValidatedStringFromTraits<TSelf, TTraits, TArchetype, TDisclosure>,
        IValidatedValueFactory<TSelf, string>
    where TTraits : IValidationTraits<string, TDisclosure>
    where TArchetype : IValidationArchetype<string>
    where TDisclosure : IDisclosurePolicy<string>
{
    protected ValidatedStringFromTraits(string validatedValue)
        : base(validatedValue)
    {
    }
}

/// <summary>A string leaf with library-enforced length bounds.</summary>
public abstract class ValidatedBoundedStringFromTraits<TSelf, TTraits, TDisclosure>
    : ValidatedStringFromTraits<
        TSelf,
        TTraits,
        BoundedStringArchetype<TTraits, TDisclosure>,
        TDisclosure>
    where TSelf : ValidatedBoundedStringFromTraits<TSelf, TTraits, TDisclosure>,
        IValidatedValueFactory<TSelf, string>
    where TTraits : IBoundedStringTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    protected ValidatedBoundedStringFromTraits(string validatedValue) : base(validatedValue) { }
}

/// <summary>A bounded string leaf with library-enforced regex whitelisting.</summary>
public abstract class ValidatedRegexStringFromTraits<TSelf, TTraits, TDisclosure>
    : ValidatedStringFromTraits<
        TSelf,
        TTraits,
        RegexStringArchetype<TTraits, TDisclosure>,
        TDisclosure>
    where TSelf : ValidatedRegexStringFromTraits<TSelf, TTraits, TDisclosure>,
        IValidatedValueFactory<TSelf, string>
    where TTraits : IRegexStringTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    protected ValidatedRegexStringFromTraits(string validatedValue) : base(validatedValue) { }
}

/// <summary>A bounded human-readable string with enforced single-line Unicode policy.</summary>
public abstract class ValidatedSingleLineFromTraits<TSelf, TTraits, TDisclosure>
    : ValidatedStringFromTraits<
        TSelf,
        TTraits,
        SingleLineTextArchetype<TTraits, TDisclosure>,
        TDisclosure>
    where TSelf : ValidatedSingleLineFromTraits<TSelf, TTraits, TDisclosure>,
        IValidatedValueFactory<TSelf, string>
    where TTraits : ISingleLineTextTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    protected ValidatedSingleLineFromTraits(string validatedValue) : base(validatedValue) { }
}

/// <summary>A bounded human-readable string with enforced multiline Unicode policy.</summary>
public abstract class ValidatedMultilineFromTraits<TSelf, TTraits, TDisclosure>
    : ValidatedStringFromTraits<
        TSelf,
        TTraits,
        MultilineTextArchetype<TTraits, TDisclosure>,
        TDisclosure>
    where TSelf : ValidatedMultilineFromTraits<TSelf, TTraits, TDisclosure>,
        IValidatedValueFactory<TSelf, string>
    where TTraits : IMultilineTextTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    protected ValidatedMultilineFromTraits(string validatedValue) : base(validatedValue) { }
}

/// <summary>Requests generation of the secure leaf constructor and factory.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class ValidatedFromTraitsAttribute<TTraits> : Attribute;
