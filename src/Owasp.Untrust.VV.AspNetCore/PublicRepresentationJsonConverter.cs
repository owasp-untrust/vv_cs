using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.AspNetCore;

internal class PublicRepresentationJsonConverter<T> : JsonConverter<T>
    where T : IPubliclyRepresentable
{
    public override bool HandleNull => true;

    public override T? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        throw new JsonException(
            $"'{typeof(T).Name}' cannot be created from JSON. Bind its locally validated candidate instead.");

    public override void Write(
        Utf8JsonWriter writer,
        T value,
        JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        if (ValidatedValueTypeInspector.IsCandidate(value.GetType()))
        {
            throw new JsonException(
                $"Incomplete candidate '{value.GetType().Name}' cannot be serialized.");
        }

        var publicValue = value.ToPublicValue();
        if (ReferenceEquals(publicValue, value))
        {
            throw new JsonException(
                $"'{value.GetType().Name}' returned itself as its public representation.");
        }

        if (publicValue is null)
        {
            writer.WriteNullValue();
            return;
        }

        JsonSerializer.Serialize(writer, publicValue, publicValue.GetType(), options);
    }
}

internal sealed class ParsableValidatedValueJsonConverter<T>
    : PublicRepresentationJsonConverter<T>
    where T : IPubliclyRepresentable, IParsable<T>
{
    public override T Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (ValidatedValueTypeInspector.IsReceiver(typeof(T)))
        {
            throw new JsonException(
                $"Cross-validated receiver '{typeof(T).Name}' cannot be deserialized.");
        }

        var raw = ReadScalarText(ref reader);
        if (!T.TryParse(raw, CultureInfo.InvariantCulture, out var result))
        {
            throw new JsonException($"The JSON value is not a valid '{typeof(T).Name}'.");
        }

        return result;
    }

    private static string ReadScalarText(ref Utf8JsonReader reader)
    {
        return reader.TokenType switch
        {
            JsonTokenType.String => reader.GetString()!,
            JsonTokenType.Number => ReadRawValue(ref reader),
            JsonTokenType.True => bool.TrueString,
            JsonTokenType.False => bool.FalseString,
            JsonTokenType.Null => throw new JsonException(
                $"JSON null is not a valid '{typeof(T).Name}'. Use Optional<{typeof(T).Name}> for optional input."),
            _ => throw new JsonException(
                $"'{typeof(T).Name}' must be represented by a JSON scalar.")
        };
    }

    private static string ReadRawValue(ref Utf8JsonReader reader)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        return document.RootElement.GetRawText();
    }
}
