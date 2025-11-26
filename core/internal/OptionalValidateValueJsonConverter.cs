using System.Text.Json;
using System.Text.Json.Serialization;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Internal;

public sealed class OptionalJsonConverter<TWrapper>
   : JsonConverter<Optional<TWrapper>>
where TWrapper : class, IQueryParsable<TWrapper> //, __IWrappableForOptional<TWrapper>
{
   private readonly JsonConverter<TWrapper> _inner;

   public OptionalJsonConverter(JsonConverter innerConverter)
   {
      _inner = (JsonConverter<TWrapper>)innerConverter
         ?? throw new ArgumentNullException(nameof(innerConverter));
   }

   // Let the converter see JSON null so it can map it to "undefined" Optional
   public override bool HandleNull => true;

   public override Optional<TWrapper> Read(
      ref Utf8JsonReader reader,
      Type typeToConvert,
      JsonSerializerOptions options)
   {
      if (reader.TokenType == JsonTokenType.Null)
      {
         // property present but null -> "no value" Optional
         // adjust to your Optional API if needed
         return default;   // Optional<TWrapper>()
      }

      var value = _inner.Read(ref reader, typeof(TWrapper), options)!;

      // adjust ctor/factory to your Optional<T> implementation
      return new Optional<TWrapper>(value);
   }

   public override void Write(
      Utf8JsonWriter writer,
      Optional<TWrapper> optional,
      JsonSerializerOptions options)
   {
      // adjust property names to your Optional<T> (IsDefined/HasValue, Value, etc.)
      if (!optional.HasValue)
      {
         writer.WriteNullValue();
         return;
      }

      _inner.Write(writer, optional.NonNull, options);
   }
}
