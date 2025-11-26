using System.Text.Json;
using System.Text.Json.Serialization;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Internal;

public sealed class ValidatedValueJsonConverter<TValidated, TPrimitive, TParser>
   : JsonConverter<TValidated>
   where TParser : IQueryParsable<TPrimitive>
   where TValidated : ValidatedValue<TValidated, TPrimitive, TParser>, ICreatable<TValidated, TPrimitive>
   where TPrimitive : notnull
{
   public override TValidated Read(ref Utf8JsonReader reader,
                                   Type typeToConvert,
                                   JsonSerializerOptions options)
   {
      var primitive = JsonSerializer.Deserialize<TPrimitive>(ref reader, options)!;
      return ValidatedValue<TValidated, TPrimitive, TParser>.Wrap(primitive);
   }

   public override void Write(Utf8JsonWriter writer,
                              TValidated value,
                              JsonSerializerOptions options)
   {
      JsonSerializer.Serialize(writer, value.Value, options);
   }
}
