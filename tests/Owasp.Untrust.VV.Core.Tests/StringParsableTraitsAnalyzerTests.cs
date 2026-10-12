using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Owasp.Untrust.VV.Analyzers;
using Xunit;

namespace Owasp.Untrust.VV.Core.Tests;

public sealed class StringParsableTraitsAnalyzerTests
{
    [Fact]
    public async Task Reports_StringTraitsWithoutStructuredPhaseJustification()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(TraitsSource("public sealed class UnsafeStringTraits : Owasp.Untrust.VV.Traits.IParsableTraits<string> { }"));

        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == "VV2008"));
        Assert.Contains("StringTraits", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("charactersValidationPerformed", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Allows_StringTraitsWithStructuredPhaseJustification()
    {
        string source = TraitsSource("""
            [Owasp.Untrust.VV.Traits.AllowStringIParsableTraits(
                "This external protocol has a reviewed reason to bypass the standard string pipeline.",
                "Bounds checked.",
                "Characters checked.",
                "Normalization checked.",
                "String rules checked.")]
            public sealed class ReviewedStringTraits : Owasp.Untrust.VV.Traits.IParsableTraits<string> { }
            """);

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "VV2008");
    }

    [Fact]
    public async Task Reports_StringTraitsWhenAnyPhaseDescriptionIsTooShort()
    {
        string source = TraitsSource("""
            [Owasp.Untrust.VV.Traits.AllowStringIParsableTraits(
                "This external protocol has a reviewed reason to bypass the standard string pipeline.",
                "Bounds checked.",
                "short",
                "Normalization checked.",
                "String rules checked.")]
            public sealed class IncompletelyReviewedStringTraits : Owasp.Untrust.VV.Traits.IParsableTraits<string> { }
            """);

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == "VV2008");
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source)
    {
        CSharpCompilation compilation = CSharpCompilation.Create(
            "AnalyzerTest",
            new[] { CSharpSyntaxTree.ParseText(source) },
            new[] { MetadataReference.CreateFromFile(typeof(object).Assembly.Location) },
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        CompilationWithAnalyzers analyzed = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new ValidatedValueAnalyzer()));
        return await analyzed.GetAnalyzerDiagnosticsAsync();
    }

    private static string TraitsSource(string declaration) => """
        namespace Owasp.Untrust.VV.Traits
        {
            public interface IParsableTraits<TValue> { }
            public sealed class AllowStringIParsableTraitsAttribute : System.Attribute
            {
                public AllowStringIParsableTraitsAttribute(string justification, string boundsValidationPerformed, string charactersValidationPerformed, string normalizationPerformed, string stringValidationPerformed) { }
            }
        }
        """ + Environment.NewLine + declaration;
}
