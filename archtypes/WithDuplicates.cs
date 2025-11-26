using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

class WithDuplicates<TValue> : List<TValue>, IValidatableObject
{
    protected static Bounds<int> _Bounds(int minLength, int maxLength) { return new Bounds<int>(minLength, maxLength); }
    public required Bounds<int> Bounds { get; init; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var count = Count;

        // Choose a member name so the error can be attached to the right place
        var memberName = validationContext.MemberName
                        ?? validationContext.DisplayName
                        ?? "Values";

        if (count < Bounds.Min)
        {
            yield return new ValidationResult(
            $"At least {Bounds.Min} values are required, but {count} were provided.",
            new[] { memberName });
        }

        if (count > Bounds.Max)
        {
            yield return new ValidationResult(
            $"At most {Bounds.Max} values are allowed, but {count} were provided.",
            new[] { memberName });
        }
    }
}
