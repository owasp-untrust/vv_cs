using System.Globalization;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.OpenApi.Models;
using Owasp.Untrust.VV.Core;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Owasp.Untrust.VV.AspNetCore;

internal sealed class ValidatedValueSchemaFilter : ISchemaFilter
{
    public void Apply(OpenApiSchema schema, SchemaFilterContext context)
    {
        var targetType = context.Type;
        var isOptional = ValidatedValueTypeInspector.IsOptional(targetType, out var optionalElement);
        if (isOptional)
        {
            targetType = optionalElement!;
        }

        if (!ValidatedValueTypeInspector.IsPubliclyRepresentable(targetType))
        {
            return;
        }

        var underlying = ValidatedValueTypeInspector.UnderlyingType(targetType) ??
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
        var nullableUnderlying = Nullable.GetUnderlyingType(type);
        if (nullableUnderlying is not null)
        {
            type = nullableUnderlying;
            schema.Nullable = true;
        }

        var primitive = Type.GetTypeCode(type) switch
        {
            TypeCode.Boolean => (Type: "boolean", Format: (string?)null),
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
            TypeCode.Char => (Type: "string", Format: null),
            TypeCode.String => (Type: "string", Format: null),
            _ when type == typeof(Guid) => (Type: "string", Format: "uuid"),
            _ when type == typeof(DateTimeOffset) => (Type: "string", Format: "date-time"),
            _ when type == typeof(DateOnly) => (Type: "string", Format: "date"),
            _ when type == typeof(TimeOnly) => (Type: "string", Format: "time"),
            _ => (Type: "string", Format: null)
        };
        schema.Type = primitive.Type;
        schema.Format = primitive.Format;

        schema.Properties = null;
        schema.Required?.Clear();
        schema.AllOf?.Clear();
        schema.OneOf?.Clear();
        schema.AnyOf?.Clear();
        schema.Reference = null;
        schema.AdditionalProperties = null;
    }

    private static void ApplyArchetypeCapabilities(OpenApiSchema schema, Type type)
    {
        if (ValidatedValueTypeInspector.TryGetStaticProperty(type, "Format", out var format) &&
            format is string formatText &&
            !string.IsNullOrWhiteSpace(formatText))
        {
            schema.Format = formatText;
        }

        if (ValidatedValueTypeInspector.TryGetStaticProperty(type, "Pattern", out var pattern))
        {
            schema.Pattern = pattern switch
            {
                Regex regex => regex.ToString(),
                string patternText => patternText,
                _ => schema.Pattern
            };
        }

        if (ValidatedValueTypeInspector.TryGetStaticProperty(type, "LengthBounds", out var lengthBounds))
        {
            if (TryReadBound<int>(lengthBounds, "Minimum", "Min", out var minimum))
            {
                schema.MinLength = minimum;
            }

            if (TryReadBound<int>(lengthBounds, "Maximum", "Max", out var maximum))
            {
                schema.MaxLength = maximum;
            }
        }

        if (ValidatedValueTypeInspector.TryGetStaticProperty(type, "Bounds", out var bounds))
        {
            if (TryReadDecimalBound(bounds, "Minimum", "Min", out var minimum))
            {
                schema.Minimum = minimum;
            }

            if (TryReadDecimalBound(bounds, "Maximum", "Max", out var maximum))
            {
                schema.Maximum = maximum;
            }
        }
    }

    private static bool TryReadBound<T>(
        object? bounds,
        string primaryName,
        string fallbackName,
        out T value)
    {
        var raw = ReadMember(bounds, primaryName) ?? ReadMember(bounds, fallbackName);
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
        var raw = ReadMember(bounds, primaryName) ?? ReadMember(bounds, fallbackName);
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

    private static object? ReadMember(object? instance, string name)
    {
        if (instance is null)
        {
            return null;
        }

        const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance;
        return instance.GetType().GetProperty(name, flags)?.GetValue(instance) ??
               instance.GetType().GetField(name, flags)?.GetValue(instance);
    }
}
