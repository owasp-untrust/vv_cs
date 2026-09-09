#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

public enum EntityAccessFailureKind
{
    NotFound,
    Forbidden
}

public interface IEntityAccessFailureDisclosure
{
    static abstract EntityAccessFailureKind MissingEntity { get; }

    static abstract EntityAccessFailureKind UnauthorizedEntity { get; }
}

public sealed class HideEntityExistence : IEntityAccessFailureDisclosure
{
    private HideEntityExistence() { }

    public static EntityAccessFailureKind MissingEntity => EntityAccessFailureKind.NotFound;

    public static EntityAccessFailureKind UnauthorizedEntity => EntityAccessFailureKind.NotFound;
}

public sealed class RevealEntityForbidden : IEntityAccessFailureDisclosure
{
    private RevealEntityForbidden() { }

    public static EntityAccessFailureKind MissingEntity => EntityAccessFailureKind.NotFound;

    public static EntityAccessFailureKind UnauthorizedEntity => EntityAccessFailureKind.Forbidden;
}

public sealed class EntityAccessException : Exception
{
    internal EntityAccessException(EntityAccessFailureKind failureKind, string? internalDenialCode = null)
        : base(failureKind == EntityAccessFailureKind.NotFound
            ? "The requested entity was not found."
            : "Access to the requested entity is forbidden.")
    {
        FailureKind = failureKind;
        ErrorCode = failureKind == EntityAccessFailureKind.NotFound
            ? "entity.not_found"
            : "entity.forbidden";
        InternalDenialCode = internalDenialCode;
    }

    public EntityAccessFailureKind FailureKind { get; }

    public string ErrorCode { get; }

    public string? InternalDenialCode { get; }
}

