using System.Text.Json;
using System.Text.Json.Serialization;
using Owasp.Untrust.VV.Core;
using static Owasp.Untrust.VV.Internal.CommonUtilities;

namespace Owasp.Untrust.VV.Internal;

public sealed class ValidatedValueJsonConverterFactory : JsonConverterFactory
{
   public override bool CanConvert(Type typeToConvert)
   {
      if (FindValidatedValueBase(typeToConvert) is not null) {
         return true;
      }

      // Optional<WrapperT> where WrapperT is a ValidatedValue<,,>
      return TryExtractOptionalInternalType(typeToConvert) is not null;
      /*if (IsOptional(typeToConvert))
      {
         var wrapperType = typeToConvert.GetGenericArguments()[0];
         return FindValidatedValueBase(wrapperType) is not null;
      }

      return false;*/
   }

   public override JsonConverter CreateConverter(Type typeToConvert,
                                                 JsonSerializerOptions options)
   {
      Type? baseType = FindValidatedValueBase(typeToConvert);      

      if (baseType == null) {
         baseType = TryExtractOptionalInternalType(typeToConvert);
         /*if (typeToConvert.IsGenericType &&
            typeToConvert.GetGenericTypeDefinition() == typeof(Optional<>))
         {      
            baseType = FindValidatedValueBase(typeToConvert.GetGenericArguments()[0]);
         }*/

         if (baseType == null)
         {
            throw new InvalidOperationException($"Type {typeToConvert} is not a ValidatedValue<,,>.");
         }

         var innerTypeConverter = CreateConverterByBaseType(baseType);
         var wrapperType = typeToConvert.GetGenericArguments()[0];
         var optionalConvType = typeof(OptionalJsonConverter<>)
                                .MakeGenericType(wrapperType);

         return (JsonConverter)Activator.CreateInstance(optionalConvType, innerTypeConverter)!;
         //return new OptionalJsonConverter<WrapperT>(innerTypeConverter);
      }
      else
      {
         return CreateConverterByBaseType(baseType);
      }
   }

   private JsonConverter CreateConverterByBaseType(Type baseType)
   {
      var genericArgs = baseType!.GetGenericArguments();
      var convType = typeof(ValidatedValueJsonConverter<,,>)
                     .MakeGenericType(genericArgs);
      return (JsonConverter)Activator.CreateInstance(convType)!;
   }

}

