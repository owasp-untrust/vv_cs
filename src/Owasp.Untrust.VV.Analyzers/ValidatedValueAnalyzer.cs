using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Owasp.Untrust.VV.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ValidatedValueAnalyzer : DiagnosticAnalyzer
{
    internal const string MustBeSealedId = "VV2001";
    internal const string ExactSelfTypeId = "VV2002";
    internal const string ConstructorVisibilityId = "VV2003";
    internal const string PublicMutableStateId = "VV2004";
    internal const string RawExposureNameId = "VV2005";
    internal const string ReceiverParsingId = "VV2006";
    internal const string CandidateExposureId = "VV2007";

    private static readonly DiagnosticDescriptor MustBeSealed = new(
        MustBeSealedId,
        "Validated-value leaves must be sealed",
        "Concrete validated-value type '{0}' must be sealed",
        "Owasp.Untrust.VV.Security",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Sealing concrete values prevents derived types from weakening their validation or disclosure policy.");

    private static readonly DiagnosticDescriptor ExactSelfType = new(
        ExactSelfTypeId,
        "Validated-value CRTP self type must be exact",
        "Validated-value type '{0}' supplies '{1}' as its self type; it must supply itself",
        "Owasp.Untrust.VV.Security",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "An exact self type is required for safe static parsing and construction.");

    private static readonly DiagnosticDescriptor ConstructorVisibility = new(
        ConstructorVisibilityId,
        "Validated-value constructors must be private",
        "Constructor for concrete validated-value type '{0}' must be private",
        "Owasp.Untrust.VV.Security",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Only Parse and TryParse may construct a concrete validated value.");

    private static readonly DiagnosticDescriptor PublicMutableState = new(
        PublicMutableStateId,
        "Validated values must not expose mutable or raw state",
        "Member '{0}' exposes public raw or mutable state on validated-value type '{1}'",
        "Owasp.Untrust.VV.Security",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Validated values must be immutable and must not expose their raw value as a property or field.");

    private static readonly DiagnosticDescriptor RawExposureName = new(
        RawExposureNameId,
        "Raw values may only escape through ExposeUnchecked",
        "Member '{0}' returns the underlying value; the only permitted escape-hatch name is 'ExposeUnchecked'",
        "Owasp.Untrust.VV.Security",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "A conspicuous, consistently named escape hatch keeps raw exposure visible during review.");

    private static readonly DiagnosticDescriptor ReceiverParsing = new(
        ReceiverParsingId,
        "Cross-validated receivers must not be request-parseable",
        "Cross-validated receiver '{0}' must not implement IParsable<T> or ISpanParsable<T>",
        "Owasp.Untrust.VV.Security",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "A receiver may only be minted by successful external or contextual validation.");

    private static readonly DiagnosticDescriptor CandidateExposure = new(
        CandidateExposureId,
        "Cross-validation candidates must not expose raw state",
        "Cross-validation candidate '{0}' must not declare ExposeUnchecked",
        "Owasp.Untrust.VV.Security",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Candidates are incomplete trust states and cannot provide a raw-value escape hatch.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(
            MustBeSealed,
            ExactSelfType,
            ConstructorVisibility,
            PublicMutableState,
            RawExposureName,
            ReceiverParsing,
            CandidateExposure);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSymbolAction(AnalyzeNamedType, SymbolKind.NamedType);
    }

    private static void AnalyzeNamedType(SymbolAnalysisContext context)
    {
        var type = (INamedTypeSymbol)context.Symbol;
        if (type.TypeKind != TypeKind.Class)
        {
            return;
        }

        var validatedBase = FindSecurityValueBase(type, out var wrappedTypeArgumentIndex);
        if (validatedBase is not null && !type.IsAbstract)
        {
            AnalyzeConcreteLeaf(context, type, validatedBase, wrappedTypeArgumentIndex);
        }

        if (ImplementsMarker(type, "ICrossValidatedValue") && ImplementsParsing(type))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                ReceiverParsing,
                FirstLocation(type),
                type.Name));
        }

        if ((ImplementsMarker(type, "ICrossValidationCandidate") ||
             ImplementsMarker(type, "IEntityResolutionCandidate")) &&
            HasPublicInstanceMethodInHierarchy(type, "ExposeUnchecked"))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                CandidateExposure,
                FirstLocation(type),
                type.Name));
        }
    }

    private static void AnalyzeConcreteLeaf(
        SymbolAnalysisContext context,
        INamedTypeSymbol type,
        INamedTypeSymbol validatedBase,
        int wrappedTypeArgumentIndex)
    {
        if (!type.IsSealed)
        {
            context.ReportDiagnostic(Diagnostic.Create(MustBeSealed, FirstLocation(type), type.Name));
        }

        if (validatedBase.TypeArguments.Length > 0 &&
            !SymbolEqualityComparer.Default.Equals(validatedBase.TypeArguments[0], type))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                ExactSelfType,
                FirstLocation(type),
                type.Name,
                validatedBase.TypeArguments[0].ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat)));
        }

        foreach (var constructor in type.InstanceConstructors)
        {
            if (constructor.DeclaredAccessibility != Accessibility.Private)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    ConstructorVisibility,
                    constructor.IsImplicitlyDeclared ? FirstLocation(type) : FirstLocation(constructor),
                    type.Name));
            }
        }

        var wrappedType = validatedBase.TypeArguments.Length > wrappedTypeArgumentIndex
            ? validatedBase.TypeArguments[wrappedTypeArgumentIndex]
            : null;

        foreach (var member in type.GetMembers())
        {
            switch (member)
            {
                case IPropertySymbol property when property.DeclaredAccessibility == Accessibility.Public:
                    if (IsForbiddenRawAlias(property.Name))
                    {
                        ReportRawAlias(context, property);
                    }
                    else if (property.SetMethod is not null ||
                             (!property.IsStatic && IsWrappedType(property.Type, wrappedType)))
                    {
                        ReportPublicState(context, property, type);
                    }

                    break;

                case IFieldSymbol field when field.DeclaredAccessibility == Accessibility.Public:
                    if (IsForbiddenRawAlias(field.Name))
                    {
                        ReportRawAlias(context, field);
                    }
                    else if (!field.IsConst &&
                             (!field.IsReadOnly ||
                              (!field.IsStatic && IsWrappedType(field.Type, wrappedType))))
                    {
                        ReportPublicState(context, field, type);
                    }

                    break;

                case IMethodSymbol method when IsPublicInstanceMethod(method):
                    AnalyzeRawMethod(context, method, wrappedType);
                    break;

                case IMethodSymbol method when
                    method.MethodKind == MethodKind.Conversion &&
                    method.DeclaredAccessibility == Accessibility.Public &&
                    IsWrappedType(method.ReturnType, wrappedType):
                    context.ReportDiagnostic(Diagnostic.Create(
                        RawExposureName,
                        FirstLocation(method),
                        method.Name));
                    break;
            }
        }
    }

    private static void AnalyzeRawMethod(
        SymbolAnalysisContext context,
        IMethodSymbol method,
        ITypeSymbol? wrappedType)
    {
        if (IsForbiddenRawAlias(method.Name) ||
            (method.Parameters.Length == 0 &&
             IsWrappedType(method.ReturnType, wrappedType) &&
             !string.Equals(method.Name, "ExposeUnchecked", StringComparison.Ordinal)))
        {
            ReportRawAlias(context, method);
        }
    }

    private static void ReportRawAlias(SymbolAnalysisContext context, ISymbol member)
    {
        context.ReportDiagnostic(Diagnostic.Create(
            RawExposureName,
            FirstLocation(member),
            member.Name));
    }

    private static void ReportPublicState(
        SymbolAnalysisContext context,
        ISymbol member,
        INamedTypeSymbol type)
    {
        context.ReportDiagnostic(Diagnostic.Create(
            PublicMutableState,
            FirstLocation(member),
            member.Name,
            type.Name));
    }

    private static INamedTypeSymbol? FindSecurityValueBase(
        INamedTypeSymbol type,
        out int wrappedTypeArgumentIndex)
    {
        for (var current = type.BaseType; current is not null; current = current.BaseType)
        {
            if (!current.ContainingNamespace.ToDisplayString().StartsWith(
                    "Owasp.Untrust.VV",
                    StringComparison.Ordinal))
            {
                continue;
            }

            if ((current.Name == "ValidatedValue" || current.Name == "CrossValidatedValue") &&
                current.Arity >= 2)
            {
                wrappedTypeArgumentIndex = 1;
                return current;
            }

            if (current.Name == "CrossValidationCandidate" && current.Arity >= 3)
            {
                wrappedTypeArgumentIndex = 1;
                return current;
            }

            if (current.Name == "EntityResolutionCandidate" && current.Arity >= 2)
            {
                wrappedTypeArgumentIndex = 1;
                return current;
            }
        }

        wrappedTypeArgumentIndex = 1;
        return null;
    }

    private static bool ImplementsMarker(INamedTypeSymbol type, string markerName) =>
        type.AllInterfaces.Any(i =>
            i.Name == markerName &&
            i.ContainingNamespace.ToDisplayString().StartsWith(
                "Owasp.Untrust.VV",
                StringComparison.Ordinal));

    private static bool ImplementsParsing(INamedTypeSymbol type) =>
        type.AllInterfaces.Any(i =>
            (i.Name == "IParsable" || i.Name == "ISpanParsable") &&
            i.ContainingNamespace.ToDisplayString() == "System");

    private static bool HasPublicInstanceMethodInHierarchy(
        INamedTypeSymbol type,
        string methodName)
    {
        for (INamedTypeSymbol? current = type; current is not null; current = current.BaseType)
        {
            if (current.GetMembers(methodName).OfType<IMethodSymbol>().Any(IsPublicInstanceMethod))
            {
                return true;
            }
        }

        return type.AllInterfaces
            .SelectMany(candidate => candidate.GetMembers(methodName))
            .OfType<IMethodSymbol>()
            .Any(method => method.DeclaredAccessibility == Accessibility.Public);
    }

    private static bool IsWrappedType(ITypeSymbol candidate, ITypeSymbol? wrappedType) =>
        wrappedType is not null && SymbolEqualityComparer.Default.Equals(candidate, wrappedType);

    private static bool IsForbiddenRawAlias(string name) => name is
        "Value" or
        "Raw" or
        "Expose" or
        "Unwrap" or
        "Reveal" or
        "RevealSensitive" or
        "GetValue" or
        "GetRawValue";

    private static bool IsPublicInstanceMethod(IMethodSymbol method) =>
        method.DeclaredAccessibility == Accessibility.Public &&
        !method.IsStatic &&
        method.MethodKind == MethodKind.Ordinary;

    private static Location FirstLocation(ISymbol symbol) =>
        symbol.Locations.FirstOrDefault(location => location.IsInSource) ?? Location.None;
}
