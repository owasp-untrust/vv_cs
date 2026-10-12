using System.Collections.Immutable;
using Microsoft.CodeAnalysis;

namespace Owasp.Untrust.VV.Analyzers;

internal sealed class ValidatedValuePolicy
{
    private const string CONFIGURATION_FILE_NAME = "vv-enforcement.json";

    private ValidatedValuePolicy(bool requireValidatedControllerRouteArguments, ImmutableArray<string> errors)
    {
        RequireValidatedControllerRouteArguments = requireValidatedControllerRouteArguments;
        Errors = errors;
    }

    public bool RequireValidatedControllerRouteArguments { get; }
    public ImmutableArray<string> Errors { get; }

    public static ValidatedValuePolicy Load(ImmutableArray<AdditionalText> additionalFiles)
    {
        bool requireValidatedControllerRouteArguments = true;
        // untrust-null-represents-no-value: No earlier configuration has supplied this optional setting.
        int configuredValue = -1;
        ImmutableArray<string>.Builder errors = ImmutableArray.CreateBuilder<string>();

        foreach (AdditionalText file in additionalFiles.Where(file => file.Path.EndsWith(CONFIGURATION_FILE_NAME, StringComparison.OrdinalIgnoreCase)))
        {
            string text = file.GetText()?.ToString() ?? string.Empty;
            if (!ReadRequireValidatedControllerRouteArguments(text, out bool exists, out bool value, out string error))
            {
                errors.Add($"Could not read '{file.Path}': {error}");
                continue;
            }

            if (!exists)
            {
                continue;
            }

            int integerValue = value ? 1 : 0;
            if (configuredValue >= 0 && configuredValue != integerValue)
            {
                errors.Add($"'requireValidatedControllerRouteArguments' has incompatible values; '{file.Path}' cannot override an earlier configuration.");
                continue;
            }

            configuredValue = integerValue;
            requireValidatedControllerRouteArguments = value;
        }

        return new ValidatedValuePolicy(requireValidatedControllerRouteArguments, errors.ToImmutable());
    }

    private static bool ReadRequireValidatedControllerRouteArguments(string text, out bool exists, out bool value, out string error)
    {
        exists = false;
        value = false;
        error = string.Empty;
        string trimmed = text.Trim();
        if (!trimmed.StartsWith("{", StringComparison.Ordinal) || !trimmed.EndsWith("}", StringComparison.Ordinal))
        {
            error = "it must be a JSON object";
            return false;
        }

        const string PROPERTY_NAME = "\"requireValidatedControllerRouteArguments\"";
        int propertyIndex = trimmed.IndexOf(PROPERTY_NAME, StringComparison.Ordinal);
        if (propertyIndex < 0)
        {
            return true;
        }

        exists = true;
        int valueStart = propertyIndex + PROPERTY_NAME.Length;
        while (valueStart < trimmed.Length && char.IsWhiteSpace(trimmed[valueStart]))
        {
            valueStart++;
        }

        if (valueStart >= trimmed.Length || trimmed[valueStart] != ':')
        {
            error = "the requireValidatedControllerRouteArguments property must have a Boolean value";
            return false;
        }

        valueStart++;
        while (valueStart < trimmed.Length && char.IsWhiteSpace(trimmed[valueStart]))
        {
            valueStart++;
        }

        if (trimmed.AsSpan(valueStart).StartsWith("true".AsSpan(), StringComparison.Ordinal))
        {
            value = true;
            return true;
        }

        if (trimmed.AsSpan(valueStart).StartsWith("false".AsSpan(), StringComparison.Ordinal))
        {
            return true;
        }

        error = "the requireValidatedControllerRouteArguments property must be true or false";
        return false;
    }
}
