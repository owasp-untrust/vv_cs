using System.Reflection;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Internal;

public sealed class OptionalPropertySchemaFilter : ISchemaFilter
{
   public void Apply(OpenApiSchema schema, SchemaFilterContext context)
   {
      // We only care about "object" schemas with properties
      if (schema.Properties == null || schema.Properties.Count == 0)
         return;

      var type = context.Type;
      var props = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);

      foreach (var prop in props)
      {
         var propType = prop.PropertyType;
         if (!propType.IsGenericType ||
             propType.GetGenericTypeDefinition() != typeof(Optional<>))
            continue;

         // Adjust to match your JSON naming policy if needed (camelCase, etc.)
         var jsonName = prop.Name;

         if (schema.Properties.TryGetValue(jsonName, out var propSchema))
         {
            // Mark the property itself as nullable
            propSchema.Nullable = true;

            // And make sure it's NOT in the "required" list of the parent DTO
            schema.Required?.Remove(jsonName);
         }
      }
   }
}
