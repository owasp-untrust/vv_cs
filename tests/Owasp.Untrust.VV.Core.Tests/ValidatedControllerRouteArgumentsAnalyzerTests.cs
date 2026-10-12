using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using Owasp.Untrust.VV.Analyzers;
using Xunit;

namespace Owasp.Untrust.VV.Core.Tests;

public sealed class ValidatedControllerRouteArgumentsAnalyzerTests
{
    [Fact]
    public async Task Reports_UnvalidatedRouteArgumentAndDtoMember()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(ControllerSource("string raw", "string Raw"));

        Assert.Equal(2, diagnostics.Count(diagnostic => diagnostic.Id == "VV2009"));
    }

    [Fact]
    public async Task Allows_ValidatedRouteArgumentAndDtoMember()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(ControllerSource("ValidatedInput raw", "ValidatedInput Raw"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "VV2009");
    }

    [Fact]
    public async Task Allows_UnvalidatedRouteArgumentsWhenDisabledInVvConfiguration()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            ControllerSource("string raw", "string Raw"),
            "{ \"requireValidatedControllerRouteArguments\": false }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "VV2009");
    }

    // untrust-null-represents-no-value: Omitting the optional test configuration exercises the secure default policy.
    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source, string? configuration = null)
    {
        CSharpCompilation compilation = CSharpCompilation.Create(
            "AnalyzerTest",
            new[] { CSharpSyntaxTree.ParseText(source) },
            new[] { MetadataReference.CreateFromFile(typeof(object).Assembly.Location) },
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        ImmutableArray<AdditionalText> additionalFiles = configuration is null
            ? ImmutableArray<AdditionalText>.Empty
            : ImmutableArray.Create<AdditionalText>(new InMemoryAdditionalText("vv-enforcement.json", configuration));
        CompilationWithAnalyzers analyzed = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new ValidatedValueAnalyzer()),
            new AnalyzerOptions(additionalFiles));
        return await analyzed.GetAnalyzerDiagnosticsAsync();
    }

    private static string ControllerSource(string parameter, string dtoMember) =>
        $$"""
        namespace Microsoft.AspNetCore.Mvc
        {
            public class ControllerBase { }
            public sealed class HttpGetAttribute : Routing.HttpMethodAttribute { }
        }
        namespace Microsoft.AspNetCore.Mvc.Routing
        {
            public abstract class HttpMethodAttribute : System.Attribute { }
        }
        namespace Owasp.Untrust.VV.Core
        {
            public abstract class ValidatedValue<TSelf, TValue, TDisclosure> { }
        }
        public sealed class ValidatedInput : Owasp.Untrust.VV.Core.ValidatedValue<ValidatedInput, string, object> { }
        public sealed class RequestDto
        {
            public {{dtoMember}} { get; set; }
        }
        public sealed class ExampleController : Microsoft.AspNetCore.Mvc.ControllerBase
        {
            [Microsoft.AspNetCore.Mvc.HttpGet]
            public void Read({{parameter}}, RequestDto dto) { }
        }
        """;

    private sealed class InMemoryAdditionalText(string path, string content) : AdditionalText
    {
        public override string Path { get; } = path;
        public override SourceText? GetText(CancellationToken cancellationToken = default) => SourceText.From(content);
    }
}
