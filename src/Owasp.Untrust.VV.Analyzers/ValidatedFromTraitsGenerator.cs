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
    private const string AttributeName =
        "Owasp.Untrust.VV.Core.ValidatedFromTraitsAttribute<TTraits>";

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
        "Traits type '{0}' must implement exactly one IValidationTraits<TValue, TDisclosure> and an enforced bounded traits contract",
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
                if (marker?.AttributeClass is not { TypeArguments.Length: 1 } attributeClass)
                {
                    continue;
                }

                INamedTypeSymbol? traits = attributeClass.TypeArguments[0] as INamedTypeSymbol;
                if (!IsValidDeclaration(type, declaration))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        InvalidDeclaration,
                        declaration.Identifier.GetLocation(),
                        type.Name));
                    continue;
                }

                INamedTypeSymbol[] contracts = traits?.AllInterfaces
                    .Where(IsValidationTraitsContract)
                    .ToArray() ?? Array.Empty<INamedTypeSymbol>();
                if (traits is null || contracts.Length != 1)
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        InvalidTraits,
                        declaration.Identifier.GetLocation(),
                        traits?.ToDisplayString() ?? "<unknown>"));
                    continue;
                }

                string? archetype = EnforcedArchetype(traits, contracts[0]);
                if (archetype is null)
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        InvalidTraits,
                        declaration.Identifier.GetLocation(),
                        traits.ToDisplayString()));
                    continue;
                }

                context.AddSource(
                    SanitizeHintName(type) + ".ValidatedFromTraits.g.cs",
                    SourceText.From(Generate(type, traits, contracts[0], archetype), Encoding.UTF8));
            }
        }
    }

    private static bool IsMarkerAttribute(AttributeData attribute) =>
        attribute.AttributeClass?.ConstructedFrom.ToDisplayString() == AttributeName;

    private static bool IsValidationTraitsContract(INamedTypeSymbol candidate) =>
        candidate.Name == "IValidationTraits" &&
        candidate.Arity == 2 &&
        candidate.ContainingNamespace.ToDisplayString() == "Owasp.Untrust.VV.Core";

    private static bool IsValidDeclaration(
        INamedTypeSymbol type,
        ClassDeclarationSyntax declaration) =>
        type.ContainingType is null &&
        type.IsSealed &&
        declaration.Modifiers.Any(SyntaxKind.PartialKeyword) &&
        type.BaseType?.SpecialType == SpecialType.System_Object;

    private static string Generate(
        INamedTypeSymbol type,
        INamedTypeSymbol traits,
        INamedTypeSymbol contract,
        string archetype)
    {
        string self = type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        string value = contract.TypeArguments[0].ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        string disclosure = contract.TypeArguments[1].ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
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
            .Append(" : global::Owasp.Untrust.VV.Core.ValidatedFromTraits<")
            .Append(self).Append(", ").Append(value).Append(", ").Append(traitsName).Append(", ")
            .Append(archetype).Append(", ").Append(disclosure).AppendLine(">,")
            .Append("    global::Owasp.Untrust.VV.Core.IValidatedValueFactory<")
            .Append(self).Append(", ").Append(value).AppendLine(">")
            .AppendLine("{")
            .Append("    private ").Append(identifier).Append('(').Append(value)
            .AppendLine(" validatedValue) : base(validatedValue) { }")
            .AppendLine()
            .Append("    static ").Append(self).Append(" global::Owasp.Untrust.VV.Core.IValidatedValueFactory<")
            .Append(self).Append(", ").Append(value).Append(">.CreateValidated(")
            .Append(value).AppendLine(" validatedValue) => new(validatedValue);");

        AppendCapabilities(source, traits, traitsName);
        source.AppendLine("}");
        return source.ToString();
    }

    private static void AppendCapabilities(
        StringBuilder source,
        INamedTypeSymbol traits,
        string traitsName)
    {
        if (HasInterface(traits, "IBoundedStringTraits"))
        {
            source.AppendLine()
                .Append("    public static global::Owasp.Untrust.VV.Archetypes.Bounds<int> LengthBounds => ")
                .Append(traitsName).AppendLine(".LengthBounds;");
        }

        if (HasInterface(traits, "IRegexStringTraits"))
        {
            source.AppendLine()
                .Append("    public static string Pattern => ").Append(traitsName).AppendLine(".Pattern;");
        }

        if (HasInterface(traits, "IWireFormatTraits"))
        {
            source.AppendLine()
                .Append("    public static string Format => ").Append(traitsName).AppendLine(".Format;");
        }
    }

    private static string? EnforcedArchetype(INamedTypeSymbol traits, INamedTypeSymbol contract)
    {
        string traitsName = traits.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        string value = contract.TypeArguments[0].ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        string disclosure = contract.TypeArguments[1].ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

        if (HasInterface(traits, "ISingleLineTextTraits"))
        {
            return $"global::Owasp.Untrust.VV.Core.SingleLineTextArchetype<{traitsName}, {disclosure}>";
        }

        if (HasInterface(traits, "IMultilineTextTraits"))
        {
            return $"global::Owasp.Untrust.VV.Core.MultilineTextArchetype<{traitsName}, {disclosure}>";
        }

        if (HasInterface(traits, "IRegexStringTraits"))
        {
            return $"global::Owasp.Untrust.VV.Core.RegexStringArchetype<{traitsName}, {disclosure}>";
        }

        if (HasInterface(traits, "IBoundedStringTraits"))
        {
            return $"global::Owasp.Untrust.VV.Core.BoundedStringArchetype<{traitsName}, {disclosure}>";
        }

        if (HasInterface(traits, "IBoundedValueTraits"))
        {
            return $"global::Owasp.Untrust.VV.Core.BoundedValueArchetype<{traitsName}, {value}, {disclosure}>";
        }

        return null;
    }

    private static bool HasInterface(INamedTypeSymbol traits, string simpleName) =>
        traits.AllInterfaces.Any(candidate =>
            candidate.Name == simpleName &&
            candidate.ContainingNamespace.ToDisplayString() == "Owasp.Untrust.VV.Core");

    private static string SanitizeHintName(INamedTypeSymbol type) =>
        type.ToDisplayString().Replace('<', '_').Replace('>', '_').Replace(',', '_').Replace(' ', '_');
}
