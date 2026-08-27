using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Owasp.Untrust.VV.AspNetCore;

internal sealed class OptionalPropertySchemaFilter : ISchemaFilter
{
    public void Apply(OpenApiSchema schema, SchemaFilterContext context)
    {
        if (schema.Properties is null || schema.Properties.Count == 0)
        {
            return;
        }

        foreach (var property in context.Type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!ValidatedValueTypeInspector.IsOptional(property.PropertyType, out _))
            {
                continue;
            }

            var declaredName = property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name;
            var candidateNames = new[]
            {
                declaredName,
                property.Name,
                JsonNamingPolicy.CamelCase.ConvertName(property.Name)
            };

            var schemaName = candidateNames.FirstOrDefault(name =>
                name is not null && schema.Properties.ContainsKey(name));
            if (schemaName is null)
            {
                continue;
            }

            schema.Properties[schemaName].Nullable = true;
            schema.Required?.Remove(schemaName);
        }
    }
}
