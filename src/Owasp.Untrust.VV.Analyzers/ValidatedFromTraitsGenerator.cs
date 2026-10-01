using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Owasp.Untrust.VV.Analyzers;

[Generator(LanguageNames.CSharp)]
public sealed class ValidatedFromTraitsGenerator : ISourceGenerator
{
    private const string ATTRIBUTE_NAME =
        "Owasp.Untrust.VV.Core.ValidatedFromTraitsAttribute<TTraits, TDisclosure>";

    private static readonly DiagnosticDescriptor InvalidDeclaration = new(
        "VVG1001",
        "Invalid generated validated-value declaration",
        "Type '{0}' must be a top-level sealed partial class with no existing base class",
        "Owasp.Untrust.VV.Generation",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor InvalidTraits = new(
        "VVG1002",
        "Traits contract is missing or ambiguous",
        "Traits type '{0}' must be either IStringTraitsAnonymousPreprocessing<TTraits> or implement IParsableTraits<TValue>",
        "Owasp.Untrust.VV.Generation",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public void Initialize(GeneratorInitializationContext context)
    {
    }

    public void Execute(GeneratorExecutionContext context)
    {
        foreach (SyntaxTree tree in context.Compilation.SyntaxTrees)
        {
            SemanticModel model = context.Compilation.GetSemanticModel(tree);
            IEnumerable<ClassDeclarationSyntax> classes = tree.GetRoot(context.CancellationToken)
                .DescendantNodes()
                .OfType<ClassDeclarationSyntax>()
                .Where(candidate => candidate.AttributeLists.Count > 0);

            foreach (ClassDeclarationSyntax declaration in classes)
            {
                if (model.GetDeclaredSymbol(declaration, context.CancellationToken) is not INamedTypeSymbol type)
                {
                    continue;
                }

                AttributeData? marker = type.GetAttributes().FirstOrDefault(IsMarkerAttribute);
                if (marker?.AttributeClass is not { TypeArguments.Length: 2 } attributeClass)
                {
                    continue;
                }

                INamedTypeSymbol? traits = attributeClass.TypeArguments[0] as INamedTypeSymbol;
                ITypeSymbol? disclosure = attributeClass.TypeArguments[1];
                if (!IsValidDeclaration(type, declaration))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        InvalidDeclaration,
                        declaration.Identifier.GetLocation(),
                        type.Name));
                    continue;
                }

                INamedTypeSymbol? parsableTraits = traits?.AllInterfaces
                    .SingleOrDefault(IsParsableTraitsContract);
                bool isStringTraits = traits is not null && InheritsStringTraits(traits);
                if (traits is not { } || disclosure is not { } || isStringTraits == (parsableTraits is not null))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        InvalidTraits,
                        declaration.Identifier.GetLocation(),
                        traits?.ToDisplayString() ?? "<unknown>"));
                    continue;
                }

                context.AddSource(
                    SanitizeHintName(type) + ".ValidatedFromTraits.g.cs",
                    SourceText.From(Generate(type, traits, parsableTraits, disclosure, isStringTraits), Encoding.UTF8));
            }
        }
    }

    private static bool IsMarkerAttribute(AttributeData attribute) =>
        attribute.AttributeClass?.ConstructedFrom.ToDisplayString() == ATTRIBUTE_NAME;

    private static bool IsParsableTraitsContract(INamedTypeSymbol candidate) =>
        candidate.Name == "IParsableTraits" &&
        candidate.Arity == 1 &&
        candidate.ContainingNamespace.ToDisplayString() == "Owasp.Untrust.VV.Core";

    private static bool InheritsStringTraits(INamedTypeSymbol traits)
    {
        for (INamedTypeSymbol? current = traits; current is not null; current = current.BaseType)
        {
            if (current.Name == "IStringTraitsAnonymousPreprocessing" &&
                current.Arity == 1 &&
                current.ContainingNamespace.ToDisplayString() == "StringPreprocessing")
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsValidDeclaration(
        INamedTypeSymbol type,
        ClassDeclarationSyntax declaration) =>
        type.ContainingType is not { } &&
        type.IsSealed &&
        declaration.Modifiers.Any(SyntaxKind.PartialKeyword) &&
        type.BaseType?.SpecialType == SpecialType.System_Object;

    private static string Generate(
        INamedTypeSymbol type,
        INamedTypeSymbol traits,
        INamedTypeSymbol? parsableTraits,
        ITypeSymbol disclosure,
        bool isStringTraits)
    {
        string self = type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        string value = isStringTraits
            ? "string"
            : parsableTraits!.TypeArguments[0].ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        string disclosureName = disclosure.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        string traitsName = traits.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        string namespaceName = type.ContainingNamespace.IsGlobalNamespace
            ? string.Empty
            : type.ContainingNamespace.ToDisplayString();
        string identifier = type.Name;

        StringBuilder source = new();
        source.AppendLine("#nullable enable");
        if (namespaceName.Length > 0)
        {
            source.Append("namespace ").Append(namespaceName).AppendLine(";");
            source.AppendLine();
        }

        source.Append("partial class ").Append(identifier)
            .Append(" : global::Owasp.Untrust.VV.Core.")
            .Append(isStringTraits ? "ExposableString<" : "ValidatedParsableFromTraits<")
            .Append(self).Append(", ")
            .Append(isStringTraits ? traitsName : value + ", " + traitsName).Append(", ")
            .Append(disclosureName).AppendLine(">,")
            .Append("    global::Owasp.Untrust.VV.Core.IValidatedValueWrapperFactory<")
            .Append(self).Append(", ").Append(value).AppendLine(">")
            .AppendLine("{")
            .Append("    private ").Append(identifier).Append('(').Append(value)
            .AppendLine(" validatedValue) : base(validatedValue) { }")
            .AppendLine()
            .Append("    static ").Append(self).Append(" global::Owasp.Untrust.VV.Core.IValidatedValueWrapperFactory<")
            .Append(self).Append(", ").Append(value).Append(">.CreateValidated(")
            .Append("global::Owasp.Untrust.VV.Core.PostValidationRawValue<")
            .Append(value).Append(", ").Append(self).Append("> validated) => new(validated.ValueForReadyConstruction);");

        AppendCapabilities(source, traits, traitsName);
        source.AppendLine("}");
        return source.ToString();
    }

    private static void AppendCapabilities(
        StringBuilder source,
        INamedTypeSymbol traits,
        string traitsName)
    {
        if (HasInterface(traits, "ILengthBoundsTraits"))
        {
            source.AppendLine()
                .Append("    public static global::Owasp.Untrust.VV.Archetypes.Bounds<int> LengthBounds => ")
                .Append(traitsName).AppendLine(".LengthBounds;");
        }

    }

    private static bool HasInterface(INamedTypeSymbol traits, string simpleName) =>
        traits.AllInterfaces.Any(candidate =>
            candidate.Name == simpleName &&
            candidate.ContainingNamespace.ToDisplayString() == "Owasp.Untrust.VV.Core");

    private static string SanitizeHintName(INamedTypeSymbol type) =>
        type.ToDisplayString().Replace('<', '_').Replace('>', '_').Replace(',', '_').Replace(' ', '_');
}
