using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

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

        string reason = ValidatedValueTypeInspector.IsCandidate(value.GetType()) ||
            ValidatedValueTypeInspector.IsPending(value.GetType())
            ? "Incomplete values cannot be serialized."
            : "The disclosure policy does not permit automatic JSON output. Register an explicit type-specific JsonConverter.";
        throw new JsonException($"'{value.GetType().Name}' cannot be serialized. {reason}");
    }
}

internal class PublicValidatedValueJsonConverter<T, TValue, TDisclosure>
    : PublicRepresentationJsonConverter<T>
    where T : IPubliclyRepresentable
    where TValue : notnull
    where TDisclosure : IPublicDisclosurePolicy<TValue>
{
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

        if (value is not IValidatedValueStorage<TValue> storage)
        {
            throw new JsonException(
                $"'{typeof(T).Name}' does not expose completed validated-value storage to the framework.");
        }

        TValue publicValue = TDisclosure.PublicValue(
            storage.GetRawValueForInternalUse());
        JsonSerializer.Serialize(writer, publicValue, options);
    }
}

internal sealed class ParsableValidatedValueJsonConverter<T>
    : PublicRepresentationJsonConverter<T>
    where T : IPubliclyRepresentable, IParsable<T>
{
    public override T Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        ReadValidated(ref reader);

    internal static T ReadValidated(ref Utf8JsonReader reader)
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

internal sealed class ParsablePublicValidatedValueJsonConverter<T, TValue, TDisclosure>
    : PublicValidatedValueJsonConverter<T, TValue, TDisclosure>
    where T : IPubliclyRepresentable, IParsable<T>
    where TValue : notnull
    where TDisclosure : IPublicDisclosurePolicy<TValue>
{
    public override T Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        ParsableValidatedValueJsonConverter<T>.ReadValidated(ref reader);
}
