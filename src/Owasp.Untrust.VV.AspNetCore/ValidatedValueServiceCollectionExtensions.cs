using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Owasp.Untrust.VV.AspNetCore;

/// <summary>
/// Registers validated-value JSON and OpenAPI integration.
/// Scalar route, query, header, and form binding uses <see cref="IParsable{TSelf}"/>
/// directly and does not require this registration.
/// </summary>
public static class ValidatedValueServiceCollectionExtensions
{
    /// <summary>
    /// Adds fail-closed JSON conversion, Optional support, and OpenAPI schema filters
    /// for validated values.
    /// </summary>
    /// <param name="services">The application's service collection.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddValidatedValues(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Configure<JsonOptions>(static options =>
            AddConverterIfMissing(options.JsonSerializerOptions));

        services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(static options =>
            AddConverterIfMissing(options.SerializerOptions));

        services.TryAddEnumerable(
            ServiceDescriptor.Transient<IConfigureOptions<SwaggerGenOptions>, ConfigureValidatedValueSwagger>());

        return services;
    }

    private static void AddConverterIfMissing(System.Text.Json.JsonSerializerOptions options)
    {
        if (!options.Converters.Any(static converter => converter is ValidatedValueJsonConverterFactory))
        {
            options.Converters.Add(new ValidatedValueJsonConverterFactory());
        }
    }
}

