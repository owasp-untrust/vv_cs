using Microsoft.OpenApi.Models;
using Xunit;
using Owasp.Untrust.VV.AspNetCore;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Owasp.Untrust.VV.Tests;

public sealed class OpenApiCapabilityTests
{
    [Fact]
    public void Schema_UsesOnlyCapabilitiesExposedByTheValueType()
    {
        OpenApiSchema schema = new();
        SchemaFilterContext context = new(typeof(SSN), null!, new SchemaRepository());

        new ValidatedValueSchemaFilter().Apply(schema, context);

        Assert.Equal("string", schema.Type);
        Assert.Equal(11, schema.MinLength);
        Assert.Equal(11, schema.MaxLength);
        Assert.Equal(SSN.Pattern, schema.Pattern);
        Assert.Equal("ssn", schema.Format);
    }

    [Fact]
    public void Schema_DoesNotInventUnsupportedCapabilities()
    {
        OpenApiSchema schema = new();
        SchemaFilterContext context = new(typeof(Phone), null!, new SchemaRepository());

        new ValidatedValueSchemaFilter().Apply(schema, context);

        Assert.Equal(3, schema.MinLength);
        Assert.Equal(20, schema.MaxLength);
        Assert.Null(schema.Pattern);
        Assert.Null(schema.Minimum);
        Assert.Null(schema.Maximum);
    }
}
