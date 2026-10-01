#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

public sealed class EntityAccessException : Exception
{
    // untrust-null-represents-no-value: Internal policy denial codes are absent for ordinary lookup and grant access failures.
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
