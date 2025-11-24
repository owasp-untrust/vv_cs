using System;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

using Owasp.Untrust.VV.Foundation;
using static Owasp.Untrust.VV.Internal.CommonUtilities;

namespace Owasp.Untrust.VV.Internal;

public sealed class ValidatedValueSchemaFilter : ISchemaFilter
{
   public void Apply(OpenApiSchema schema, SchemaFilterContext context)
   {
      bool isRequired = true;
      var validatedBase = FindValidatedValueBase(context.Type);
      if (validatedBase is null) {
         validatedBase = TryExtractOptionalInternalType(context.Type);
         if (validatedBase is null) {
            return;
         }
         isRequired = false;
      }

      // <WrapperT, ValueT, ParserT>
      var args = validatedBase.GetGenericArguments();
      var valueType = args[1];

      if (!TryGetPrimitiveSchema(valueType, out var primitive))
         return;

      // Rewrite schema to look like the primitive
      schema.Type = primitive.Type;
      schema.Format = primitive.Format;
      schema.Nullable = !isRequired; //primitive.Nullable;

      schema.Properties = null;
      schema.AllOf = null;
      schema.Reference = null;
   }

   private static bool TryGetPrimitiveSchema(Type t, out OpenApiSchema schema)
   {
      schema = null!;

      if (t == typeof(int))
      {
         schema = new OpenApiSchema { Type = "integer", Format = "int32" };
         return true;
      }

      if (t == typeof(long))
      {
         schema = new OpenApiSchema { Type = "integer", Format = "int64" };
         return true;
      }

      if (t == typeof(string))
      {
         schema = new OpenApiSchema { Type = "string" };
         return true;
      }

      if (t == typeof(bool))
      {
         schema = new OpenApiSchema { Type = "boolean" };
         return true;
      }

      if (t == typeof(double) || t == typeof(float) || t == typeof(decimal))
      {
         schema = new OpenApiSchema { Type = "number" };
         return true;
      }

      if (t == typeof(DateTime) || t == typeof(DateTimeOffset))
      {
         schema = new OpenApiSchema { Type = "string", Format = "date-time" };
         return true;
      }

      // Add more primitives as needed

      return false;
   }
}
