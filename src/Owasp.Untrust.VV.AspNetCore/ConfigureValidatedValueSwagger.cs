using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Owasp.Untrust.VV.AspNetCore;

internal sealed class ConfigureValidatedValueSwagger : IConfigureOptions<SwaggerGenOptions>
{
    public void Configure(SwaggerGenOptions options)
    {
        options.SchemaFilter<ValidatedValueSchemaFilter>();
        options.SchemaFilter<OptionalPropertySchemaFilter>();
    }
}
