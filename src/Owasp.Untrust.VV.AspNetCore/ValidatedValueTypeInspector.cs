using System.Reflection;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.AspNetCore;

internal static class ValidatedValueTypeInspector
{
    internal const string CANDIDATE_MARKER_NAME = "Owasp.Untrust.VV.CrossValidation.ICrossValidationCandidate";
    internal const string ENTITY_CANDIDATE_MARKER_NAME = "Owasp.Untrust.VV.EntityAccess.IEntityResolutionCandidate";
    internal const string RECEIVER_MARKER_NAME = "Owasp.Untrust.VV.CrossValidation.ICrossValidatedValue";
    internal const string AUTHORIZED_ENTITY_MARKER_NAME = "Owasp.Untrust.VV.EntityAccess.IAuthorizedEntity";

    internal static bool IsPubliclyRepresentable(Type type) =>
        typeof(IPubliclyRepresentable).IsAssignableFrom(type);

    internal static bool IsCandidate(Type type) =>
        ImplementsMarker(type, CANDIDATE_MARKER_NAME) ||
        ImplementsMarker(type, ENTITY_CANDIDATE_MARKER_NAME);

    internal static bool IsReceiver(Type type) => ImplementsMarker(type, RECEIVER_MARKER_NAME);

    internal static bool IsAuthorizedEntity(Type type) =>
        ImplementsMarker(type, AUTHORIZED_ENTITY_MARKER_NAME);

    internal static bool IsSelfParsable(Type type) =>
        type.GetInterfaces().Any(candidate =>
            candidate.IsGenericType &&
            candidate.GetGenericTypeDefinition() == typeof(IParsable<>) &&
            candidate.GenericTypeArguments[0] == type);

    internal static bool IsOptional(Type type, out Type? elementType)
    {
        if (type.IsGenericType &&
            type.GetGenericTypeDefinition().FullName == "Owasp.Untrust.VV.Core.Optional`1")
        {
            elementType = type.GenericTypeArguments[0];
            return true;
        }

        elementType = null;
        return false;
    }

    internal static Type? FindValidatedValueBase(Type type)
    {
        for (Type? current = type; current is not null; current = current.BaseType)
        {
            if (current.IsGenericType &&
                current.GetGenericTypeDefinition().FullName is
                    "Owasp.Untrust.VV.Core.ValidatedValue`3" or
                    "Owasp.Untrust.VV.CrossValidation.CrossValidatedValue`3" or
                    "Owasp.Untrust.VV.CrossValidation.CrossValidationCandidate`5")
            {
                return current;
            }
        }

        return null;
    }

    internal static Type? UnderlyingType(Type type)
    {
        var securedBase = FindValidatedValueBase(type);
        if (securedBase is null)
        {
            return null;
        }

        var argumentIndex = securedBase.GetGenericTypeDefinition().FullName ==
            "Owasp.Untrust.VV.CrossValidation.CrossValidationCandidate`5"
            ? 2
            : 1;
        return securedBase.GenericTypeArguments.ElementAtOrDefault(argumentIndex);
    }

    internal static bool TryGetStaticProperty(Type type, string simpleName, out object? value)
    {
        const BindingFlags FLAGS =
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.FlattenHierarchy;

        var property = type
            .GetProperties(FLAGS)
            .FirstOrDefault(candidate =>
                candidate.GetIndexParameters().Length == 0 &&
                (candidate.Name == simpleName ||
                 candidate.Name.EndsWith('.' + simpleName, StringComparison.Ordinal)));

        if (property is null)
        {
            value = null;
            return false;
        }

        try
        {
            value = property.GetValue(null);
            return true;
        }
        catch (TargetInvocationException)
        {
            value = null;
            return false;
        }
        catch (MethodAccessException)
        {
            value = null;
            return false;
        }
    }

    private static bool ImplementsMarker(Type type, string fullName) =>
        type.GetInterfaces().Any(candidate => candidate.FullName == fullName);
}
