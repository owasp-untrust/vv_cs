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

        foreach (PropertyInfo property in context.Type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!ValidatedValueTypeInspector.TryExtractOptionalElement(property.PropertyType, out _))
            {
                continue;
            }

            string? declaredName = property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name;
            string?[] candidateNames = new[]
            {
                declaredName,
                property.Name,
                JsonNamingPolicy.CamelCase.ConvertName(property.Name)
            };

            string? schemaName = candidateNames.FirstOrDefault(name =>
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
