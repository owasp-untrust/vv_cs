using System.Text.Json;
using System.Text.Json.Serialization;

namespace Owasp.Untrust.VV.AspNetCore;

internal sealed class ValidatedValueJsonConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        ValidatedValueTypeInspector.IsPubliclyRepresentable(typeToConvert) ||
        ValidatedValueTypeInspector.IsAuthorizedEntity(typeToConvert) ||
        ValidatedValueTypeInspector.IsOptional(typeToConvert, out _);

    public override JsonConverter CreateConverter(
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (ValidatedValueTypeInspector.IsOptional(typeToConvert, out var elementType))
        {
            var optionalConverter = typeof(OptionalJsonConverter<>).MakeGenericType(elementType!);
            return (JsonConverter)Activator.CreateInstance(optionalConverter)!;
        }

        if (ValidatedValueTypeInspector.IsAuthorizedEntity(typeToConvert))
        {
            var evidenceConverter = typeof(AuthorizedEntityJsonConverter<>)
                .MakeGenericType(typeToConvert);
            return (JsonConverter)Activator.CreateInstance(evidenceConverter)!;
        }

        if (!ValidatedValueTypeInspector.IsPubliclyRepresentable(typeToConvert))
        {
            throw new InvalidOperationException(
                $"Type '{typeToConvert}' is not a publicly representable validated value.");
        }

        var converterType = ValidatedValueTypeInspector.IsSelfParsable(typeToConvert)
            ? typeof(ParsableValidatedValueJsonConverter<>).MakeGenericType(typeToConvert)
            : typeof(PublicRepresentationJsonConverter<>).MakeGenericType(typeToConvert);

        return (JsonConverter)Activator.CreateInstance(converterType)!;
    }
}

internal sealed class AuthorizedEntityJsonConverter<T> : JsonConverter<T>
{
    public override T? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        throw new JsonException(
            $"Authorization evidence '{typeof(T).Name}' cannot be created from JSON.");

    public override void Write(
        Utf8JsonWriter writer,
        T value,
        JsonSerializerOptions options) =>
        throw new JsonException(
            $"Authorization evidence '{typeof(T).Name}' cannot be serialized.");
}
