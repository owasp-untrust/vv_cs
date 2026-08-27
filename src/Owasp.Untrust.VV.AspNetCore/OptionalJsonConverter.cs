using System.Text.Json;
using System.Text.Json.Serialization;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.AspNetCore;

internal sealed class OptionalJsonConverter<T> : JsonConverter<Optional<T>>
    where T : IParsable<T>
{
    public override bool HandleNull => true;

    public override Optional<T> Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return Optional<T>.None;
        }

        var parsed = JsonSerializer.Deserialize<T>(ref reader, options);
        if (parsed is null)
        {
            throw new JsonException($"The JSON value is not a valid '{typeof(T).Name}'.");
        }

        return Optional<T>.Some(parsed);
    }

    public override void Write(
        Utf8JsonWriter writer,
        Optional<T> value,
        JsonSerializerOptions options)
    {
        if (!value.HasValue)
        {
            writer.WriteNullValue();
            return;
        }

        JsonSerializer.Serialize(writer, value.NonNull, options);
    }
}
