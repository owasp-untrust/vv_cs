#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Core;

/// <summary>An explicit optional value suitable for request DTOs.</summary>
public readonly struct Optional<T> : IParsable<Optional<T>>
    where T : IParsable<T>
{
    private readonly T? _value;

    private Optional(T value)
    {
        _value = value ?? throw new ArgumentNullException(nameof(value));
        HasValue = true;
    }

    public bool HasValue { get; }

    public T NonNull => HasValue
        ? _value!
        : throw new InvalidOperationException("The optional value is absent.");

    public T? PossiblyNull => HasValue ? _value : default;

    public static Optional<T> None => default;

    public static Optional<T> Some(T value) => new(value);

    public static Optional<T> Parse(string raw, IFormatProvider? provider)
    {
        ArgumentNullException.ThrowIfNull(raw);
        return Some(T.Parse(raw, provider));
    }

    public static bool TryParse(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out Optional<T> result)
    {
        if (raw is null)
        {
            result = None;
            return true;
        }

        if (T.TryParse(raw, provider, out var parsed))
        {
            result = Some(parsed);
            return true;
        }

        result = None;
        return false;
    }
}
