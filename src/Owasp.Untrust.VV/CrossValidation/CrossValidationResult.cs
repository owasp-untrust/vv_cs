#pragma warning disable CS1591
namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>A safe, value-free result returned by a domain cross-validation check.</summary>
public readonly record struct CrossValidationResult
{
    private CrossValidationResult(bool succeeded, string? errorCode, string? safeMessage)
    {
        Succeeded = succeeded;
        ErrorCode = errorCode;
        SafeMessage = safeMessage;
    }

    public bool Succeeded { get; }

    public string? ErrorCode { get; }

    public string? SafeMessage { get; }

    public static CrossValidationResult Success { get; } = new(true, null, null);

    public static CrossValidationResult Failure(string errorCode, string safeMessage)
    {
        if (string.IsNullOrWhiteSpace(errorCode))
        {
            throw new ArgumentException("An error code must not be blank.", nameof(errorCode));
        }

        if (string.IsNullOrWhiteSpace(safeMessage))
        {
            throw new ArgumentException("A safe error message must not be blank.", nameof(safeMessage));
        }

        return new CrossValidationResult(false, errorCode, safeMessage);
    }
}
