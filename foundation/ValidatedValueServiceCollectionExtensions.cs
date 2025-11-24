using System.Text.Json;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Swashbuckle.AspNetCore.SwaggerGen;
using Owasp.Untrust.VV.Internal;

public static class ValidatedValueServiceCollectionExtensions
{
   public static IServiceCollection AddValidatedValues(this IServiceCollection services)
   {
      ValidatedValueJsonConverterFactory jsonConverterFactory = new ValidatedValueJsonConverterFactory();

      // JSON: controllers
      services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(o =>
      {
         o.JsonSerializerOptions.Converters.Add(jsonConverterFactory);
      });

      // JSON: minimal APIs / Http.Json
      services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(o =>
      {
         o.SerializerOptions.Converters.Add(jsonConverterFactory);
      });

      // Swagger schemas (only used if AddSwaggerGen is called somewhere)
      services.Configure<SwaggerGenOptions>(o =>
      {
         o.SchemaFilter<ValidatedValueSchemaFilter>();
         o.SchemaFilter<OptionalPropertySchemaFilter>();
      });

      return services;
   }
}
