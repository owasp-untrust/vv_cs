using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Core;

public interface IQueryParsable<TValue>
{
    //
    // Summary:
    //     Tries to parse a string into a value.
    //
    // Parameters:
    //   s:
    //     The string to parse.
    //
    //   provider:
    //     An object that provides culture-specific formatting information about s.
    //
    //   result:
    //     When this method returns, contains the result of successfully parsing s or an
    //     undefined value on failure.
    //
    // Returns:
    //     true if s was successfully parsed; otherwise, false.
    static abstract bool TryParse(string? s, IFormatProvider? provider, [MaybeNullWhen(false)] out TValue result);
}
