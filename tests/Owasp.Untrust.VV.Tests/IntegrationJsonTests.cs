using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.AspNetCore;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.CrossValidation;
using Owasp.Untrust.VV.EntityAccess;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Xunit;

namespace Owasp.Untrust.VV.Tests;

/// <summary>Exercises the ASP.NET JSON integration's security boundaries.</summary>
public sealed class IntegrationJsonTests
{
    /// <summary>JSON input delegates to the validated type's IParsable implementation.</summary>
    [Fact]
    public void AddValidatedValues_UsesTheIParsableValidationPath()
    {
        var options = CreateJsonOptions();

        var parsed = JsonSerializer.Deserialize<IntegrationPublicText>("\"valid\"", options);

        Assert.NotNull(parsed);
        Assert.Equal("valid", parsed!.ExposeUnchecked());

        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<IntegrationPublicText>(
                "\"this rejected value is far too long\"",
                options));
        Assert.DoesNotContain("this rejected value", exception.Message);
    }

    /// <summary>Only a public disclosure policy enables automatic JSON output.</summary>
    [Fact]
    public void Serialization_RequiresPublicDisclosurePolicy()
    {
        var options = CreateJsonOptions();
        var publicValue = IntegrationPublicText.Parse("visible", provider: null);
        var publicNumber = IntegrationPublicPortPoc.Parse("443", provider: null);
        var secret = IntegrationSecretText.Parse("private", provider: null);

        Assert.Equal("\"visible\"", JsonSerializer.Serialize(publicValue, options));
        Assert.Equal("443", JsonSerializer.Serialize(publicNumber, options));
        JsonException exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Serialize(secret, options));
        Assert.DoesNotContain("private", exception.Message);
        Assert.Contains("explicit type-specific JsonConverter", exception.Message);
    }

    /// <summary>An application can explicitly choose a non-public type's JSON representation.</summary>
    [Fact]
    public void TypeSpecificConverter_CanOptNonPublicTypeIntoSerialization()
    {
        var options = CreateJsonOptions();
        options.Converters.Insert(0, new IntegrationSecretTextJsonConverter());
        var secret = IntegrationSecretText.Parse("private", provider: null);

        Assert.Equal("\"[sensitive]\"", JsonSerializer.Serialize(secret, options));
    }

    /// <summary>Optional values preserve Some/None semantics in JSON.</summary>
    [Fact]
    public void Optional_MapsNullToNoneAndScalarsToSome()
    {
        var options = CreateJsonOptions();

        var none = JsonSerializer.Deserialize<Optional<IntegrationPublicText>>("null", options);
        var some = JsonSerializer.Deserialize<Optional<IntegrationPublicText>>("\"valid\"", options);

        Assert.False(none.HasValue);
        Assert.True(some.HasValue);
        Assert.Equal("valid", some.NonNull.ExposeUnchecked());
        Assert.Equal("null", JsonSerializer.Serialize(Optional<IntegrationPublicText>.None, options));
        Assert.Equal("\"valid\"", JsonSerializer.Serialize(some, options));
    }

    /// <summary>Incomplete candidates cannot leave the service and receivers cannot enter it.</summary>
    [Fact]
    public void CandidateOutputAndReceiverInputFailClosed()
    {
        var options = CreateJsonOptions();
        var candidate = IntegrationCandidate.Parse("locally-valid", provider: null);
        var pending = IntegrationPending.Parse("locally-valid", provider: null);

        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(candidate, options));
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(pending, options));
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<IntegrationReceiver>("\"trusted\"", options));
    }

    [Fact]
    public void EntityCandidateAndAuthorizationEvidenceFailClosedAtJsonBoundary()
    {
        var options = CreateJsonOptions();
        var candidate = IntegrationEntityCandidate.Parse("document-1", provider: null);
        var evidence = (AuthorizedEntity<string, IntegrationRead>)Activator.CreateInstance(
            typeof(AuthorizedEntity<string, IntegrationRead>),
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args: ["stored entity"],
            culture: null)!;

        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(candidate, options));
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(evidence, options));
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<AuthorizedEntity<string, IntegrationRead>>("{}", options));
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var services = new ServiceCollection();
        services.AddValidatedValues();
        using var provider = services.BuildServiceProvider();
        return new JsonSerializerOptions(
            provider.GetRequiredService<IOptions<JsonOptions>>().Value.SerializerOptions);
    }

    private sealed class IntegrationPublicText :
        BoundedString<IntegrationPublicText, Public<string>>,
        IBoundedStringDefinition,
        IParsable<IntegrationPublicText>
    {
        private IntegrationPublicText(string raw, IFormatProvider? provider)
            : base(raw, provider)
        {
        }

        public static Bounds<int> LengthBounds => new(1, 16);

        public static IntegrationPublicText Parse(string raw, IFormatProvider? provider) =>
            new(raw, provider);

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationPublicText result)
        {
            var succeeded = TryParseCore(
                raw,
                provider,
                static (value, formatProvider) => new IntegrationPublicText(value, formatProvider),
                out var parsed);
            result = parsed!;
            return succeeded;
        }
    }

    private sealed class IntegrationSecretText :
        BoundedString<IntegrationSecretText, RedactedSecret<string>>,
        IBoundedStringDefinition,
        IParsable<IntegrationSecretText>
    {
        private IntegrationSecretText(string raw, IFormatProvider? provider)
            : base(raw, provider)
        {
        }

        public static Bounds<int> LengthBounds => new(1, 16);

        public static IntegrationSecretText Parse(string raw, IFormatProvider? provider) =>
            new(raw, provider);

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationSecretText result)
        {
            var succeeded = TryParseCore(
                raw,
                provider,
                static (value, formatProvider) => new IntegrationSecretText(value, formatProvider),
                out var parsed);
            result = parsed!;
            return succeeded;
        }
    }

    private sealed class IntegrationPublicPortPoc :
        BoundedNumber<IntegrationPublicPortPoc, int, Public<int>>,
        IBoundedNumberDefinition<int>,
        IParsable<IntegrationPublicPortPoc>
    {
        private IntegrationPublicPortPoc(string raw, IFormatProvider? provider)
            : base(raw, provider)
        {
        }

        public static Bounds<int> Bounds => new(1, 65535);

        public static IntegrationPublicPortPoc Parse(string raw, IFormatProvider? provider) =>
            new(raw, provider);

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationPublicPortPoc result) =>
            TryParseCore(
                raw,
                provider,
                static (value, formatProvider) =>
                    new IntegrationPublicPortPoc(value, formatProvider),
                out result);
    }

    private sealed class IntegrationCandidate :
        ICrossValidationCandidate,
        IParsable<IntegrationCandidate>
    {
        private readonly string _value;

        private IntegrationCandidate(string value)
        {
            _value = value;
        }

        public Type ReceiverType => typeof(IntegrationReceiver);

        public string ToPublicString() => _value;

        public static IntegrationCandidate Parse(string raw, IFormatProvider? provider)
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(raw));

            return new IntegrationCandidate(raw);
        }

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationCandidate result)
        {
            if (!string.IsNullOrWhiteSpace(raw))
            {
                result = new IntegrationCandidate(raw);
                return true;
            }

            result = null!;
            return false;
        }
    }

    private sealed class IntegrationReceiver : ICrossValidatedValue
    {
        public Type ValueType => typeof(string);

        public string ToPublicString() => "trusted";
    }

    private sealed class IntegrationPending : IPendingValue, IParsable<IntegrationPending>
    {
        private readonly string _value;

        private IntegrationPending(string value) => _value = value;

        public string ToPublicString() => _value;

        public static IntegrationPending Parse(string raw, IFormatProvider? provider) =>
            !string.IsNullOrWhiteSpace(raw)
                ? new IntegrationPending(raw)
                : throw new ArgumentException("Value cannot be null or whitespace.", nameof(raw));

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationPending result)
        {
            if (!string.IsNullOrWhiteSpace(raw))
            {
                result = new IntegrationPending(raw);
                return true;
            }

            result = null!;
            return false;
        }
    }

    private sealed class IntegrationRead : IEntityOperation;

    private sealed class IntegrationEntityCandidate :
        IEntityResolutionCandidate,
        IParsable<IntegrationEntityCandidate>
    {
        private readonly string _id;

        private IntegrationEntityCandidate(string id)
        {
            _id = id;
        }

        public Type EntityIdType => typeof(string);

        public string ToPublicString() => _id;

        public static IntegrationEntityCandidate Parse(string raw, IFormatProvider? provider)
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(raw));

            return new IntegrationEntityCandidate(raw);
        }

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationEntityCandidate result)
        {
            if (!string.IsNullOrWhiteSpace(raw))
            {
                result = new IntegrationEntityCandidate(raw);
                return true;
            }

            result = null!;
            return false;
        }
    }

    private sealed class IntegrationSecretTextJsonConverter : JsonConverter<IntegrationSecretText>
    {
        public override IntegrationSecretText Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options) =>
            IntegrationSecretText.Parse(reader.GetString()!, provider: null);

        public override void Write(
            Utf8JsonWriter writer,
            IntegrationSecretText value,
            JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToPublicString());
    }
}
