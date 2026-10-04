using System.Text.Json;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.AspNetCore;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.StringPreprocessing;
using Owasp.Untrust.VV.Traits;
using Xunit;

namespace Owasp.Untrust.VV.AspNetCore.Tests;

public sealed class GeneratedTraitsTests
{
    [Fact]
    public void GeneratedLeaf_IsJsonBindableThroughInheritedIParsable()
    {
        ServiceCollection services = new();
        services.AddValidatedValues();
        using ServiceProvider provider = services.BuildServiceProvider();
        JsonSerializerOptions options = provider
            .GetRequiredService<IOptions<JsonOptions>>()
            .Value.SerializerOptions;

        GeneratedJsonSlug? value = JsonSerializer.Deserialize<GeneratedJsonSlug>("\"  ABC  \"", options);

        Assert.NotNull(value);
        Assert.Equal("abc", value.ExposeUnchecked());
    }
}

[ValidatedFromTraits<GeneratedJsonSlugTraits, Public<string>>]
public sealed partial class GeneratedJsonSlug
{
}

public sealed class GeneratedJsonSlugTraits
    : StringTraits<GeneratedJsonSlugTraits, GeneratedJsonSlugValidation>,
      ILengthBoundsTraits<GeneratedJsonSlugTraits>
{
    public static Bounds<int> LengthBounds => new(1, 32);
}

public readonly struct GeneratedJsonSlugValidation : ICharactersValidator, IStringNormalizer, IStringValidator
{
    public string NormalizeBeforeValidation(string raw) => raw.Trim().ToLowerInvariant();

    public ValidationIssue? ValidateCharacters(string value) => null;

    public ValidationIssue? ValidateString(string value) => null;
}
