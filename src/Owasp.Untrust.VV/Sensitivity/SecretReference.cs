#pragma warning disable CS1591
using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Sensitivity;

/// <summary>
/// A bounded, relative logical path into a secret store. This is an identifier, not
/// secret material.
/// </summary>
public sealed class SecretReference : IEquatable<SecretReference>
{
    public const int MAXIMUM_LENGTH = 512;

    public SecretReference(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A secret reference must not be blank.", nameof(path));
        }

        if (path.Length > MAXIMUM_LENGTH)
        {
            throw new ArgumentOutOfRangeException(
                nameof(path),
                $"A secret reference must not exceed {MAXIMUM_LENGTH} characters.");
        }

        if (path[0] is '/' or '\\' ||
            (path.Length >= 2 && char.IsAsciiLetter(path[0]) && path[1] == ':'))
        {
            throw new ArgumentException("A secret reference must be relative.", nameof(path));
        }

        if (path.Any(char.IsControl))
        {
            throw new ArgumentException(
                "A secret reference must not contain control characters.",
                nameof(path));
        }

        string[] segments = path.Split(['/', '\\']);
        if (segments.Any(static segment =>
                segment.Length == 0 || segment is "." or ".."))
        {
            throw new ArgumentException(
                "A secret reference must contain only bounded path segments.",
                nameof(path));
        }

        Path = path;
    }

    public string Path { get; }

    public bool Equals(SecretReference? other) =>
        other is not null && string.Equals(Path, other.Path, StringComparison.Ordinal);

    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is SecretReference other && Equals(other);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Path);

    public override string ToString() => "[secret reference]";
}
