using System.Globalization;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Diagnostics.CodeAnalysis;
using Microsoft.OpenApi.Models;
using Owasp.Untrust.VV.Core;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Owasp.Untrust.VV.AspNetCore;

internal sealed class ValidatedValueSchemaFilter : ISchemaFilter
{
    public void Apply(OpenApiSchema schema, SchemaFilterContext context)
    {
        Type targetType = context.Type;
        bool isOptional = ValidatedValueTypeInspector.TryExtractOptionalElement(targetType, out Type? optionalElement);
        if (isOptional)
        {
            targetType = optionalElement!;
        }

        if (!ValidatedValueTypeInspector.IsPubliclyRepresentable(targetType))
        {
            return;
        }

        Type underlying = ValidatedValueTypeInspector.UnderlyingType(targetType) ??
                         typeof(string);
        RewriteAsPrimitive(schema, underlying);
        schema.Nullable = isOptional;

        ApplyArchetypeCapabilities(schema, targetType);

        if (ValidatedValueTypeInspector.IsCandidate(targetType))
        {
            schema.WriteOnly = true;
        }
        else if (ValidatedValueTypeInspector.IsReceiver(targetType))
        {
            schema.ReadOnly = true;
        }
    }

    private static void RewriteAsPrimitive(OpenApiSchema schema, Type type)
    {
        Type? nullableUnderlying = Nullable.GetUnderlyingType(type);
        if (nullableUnderlying is not null)
        {
            type = nullableUnderlying;
            schema.Nullable = true;
        }

        (string Type, string? Format) primitive = Type.GetTypeCode(type) switch
        {
            TypeCode.Boolean => (Type: "boolean", Format: (string?)null), // untrust-null-represents-no-value: Boolean primitives have no additional OpenAPI wire format
            TypeCode.Byte => (Type: "integer", Format: "int32"),
            TypeCode.SByte => (Type: "integer", Format: "int32"),
            TypeCode.Int16 => (Type: "integer", Format: "int32"),
            TypeCode.UInt16 => (Type: "integer", Format: "int32"),
            TypeCode.Int32 => (Type: "integer", Format: "int32"),
            TypeCode.UInt32 => (Type: "integer", Format: "int64"),
            TypeCode.Int64 => (Type: "integer", Format: "int64"),
            TypeCode.UInt64 => (Type: "integer", Format: "int64"),
            TypeCode.Single => (Type: "number", Format: "float"),
            TypeCode.Double => (Type: "number", Format: "double"),
            TypeCode.Decimal => (Type: "number", Format: "decimal"),
            TypeCode.DateTime => (Type: "string", Format: "date-time"),
            TypeCode.Char => (Type: "string", Format: null), // untrust-null-represents-no-value: character primitives have no additional OpenAPI wire format
            TypeCode.String => (Type: "string", Format: null), // untrust-null-represents-no-value: string primitives have no additional OpenAPI wire format
            _ when type == typeof(Guid) => (Type: "string", Format: "uuid"),
            _ when type == typeof(DateTimeOffset) => (Type: "string", Format: "date-time"),
            _ when type == typeof(DateOnly) => (Type: "string", Format: "date"),
            _ when type == typeof(TimeOnly) => (Type: "string", Format: "time"),
            _ => (Type: "string", Format: null) // untrust-null-represents-no-value: unknown primitives use the unconstrained string wire format
        };
        schema.Type = primitive.Type;
        schema.Format = primitive.Format;

        schema.Properties = null; // untrust-null-represents-no-value: primitive schemas cannot retain object properties from the replaced component
        schema.Required?.Clear();
        schema.AllOf?.Clear();
        schema.OneOf?.Clear();
        schema.AnyOf?.Clear();
        schema.Reference = null; // untrust-null-represents-no-value: primitive rewrite must remove the prior component schema reference
        schema.AdditionalProperties = null; // untrust-null-represents-no-value: primitive schemas do not define object additional-properties metadata
    }

    private static void ApplyArchetypeCapabilities(OpenApiSchema schema, Type type)
    {
        if (ValidatedValueTypeInspector.TryGetStaticProperty(type, "Format", out object? format) &&
            format is string formatText &&
            !string.IsNullOrWhiteSpace(formatText))
        {
            schema.Format = formatText;
        }

        if (ValidatedValueTypeInspector.TryGetStaticProperty(type, "Pattern", out object? pattern))
        {
            schema.Pattern = pattern switch
            {
                Regex regex => regex.ToString(),
                string patternText => patternText,
                _ => schema.Pattern
            };
        }

        if (ValidatedValueTypeInspector.TryGetStaticProperty(type, "LengthBounds", out object? lengthBounds))
        {
            if (TryReadBound<int>(lengthBounds, "Minimum", "Min", out int minimum))
            {
                schema.MinLength = minimum;
            }

            if (TryReadBound<int>(lengthBounds, "Maximum", "Max", out int maximum))
            {
                schema.MaxLength = maximum;
            }
        }

        if (ValidatedValueTypeInspector.TryGetStaticProperty(type, "Bounds", out object? bounds))
        {
            if (TryReadDecimalBound(bounds, "Minimum", "Min", out decimal minimum))
            {
                schema.Minimum = minimum;
            }

            if (TryReadDecimalBound(bounds, "Maximum", "Max", out decimal maximum))
            {
                schema.Maximum = maximum;
            }
        }
    }

    private static bool TryReadBound<T>(
        object? bounds,
        string primaryName,
        string fallbackName,
        [MaybeNullWhen(false)] out T value)
    {
        if (bounds is null)
        {
            value = default;
            return false;
        }

        object? raw = ReadMember(bounds, primaryName) ?? ReadMember(bounds, fallbackName);
        if (raw is T typed)
        {
            value = typed;
            return true;
        }

        value = default!;
        return false;
    }

    private static bool TryReadDecimalBound(
        object? bounds,
        string primaryName,
        string fallbackName,
        out decimal value)
    {
        if (bounds is null)
        {
            value = default;
            return false;
        }

        object? raw = ReadMember(bounds, primaryName) ?? ReadMember(bounds, fallbackName);
        if (raw is null)
        {
            value = default;
            return false;
        }

        return TryConvertDecimal(raw, out value);
    }

    private static bool TryConvertDecimal(object raw, out decimal value)
    {
        try
        {
            value = Convert.ToDecimal(raw, CultureInfo.InvariantCulture);
            return true;
        }
        catch (Exception exception) when (
            exception is FormatException or InvalidCastException or OverflowException)
        {
            value = default;
            return false;
        }
    }

    private static object? ReadMember(object instance, string name)
    {
        const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance;
        return instance.GetType().GetProperty(name, flags)?.GetValue(instance) ??
               instance.GetType().GetField(name, flags)?.GetValue(instance);
    }
}
