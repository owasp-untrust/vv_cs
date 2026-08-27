#pragma warning disable CS1591
using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Sensitivity;

/// <summary>
/// An immutable owner of binary transformation output. Input and output buffers are
/// copied so a provider or caller cannot mutate a stored hash, nonce, tag, or
/// ciphertext after construction.
/// </summary>
public sealed class BinaryArtifact : IEquatable<BinaryArtifact>
{
    private readonly byte[] _bytes;

    public BinaryArtifact(ReadOnlySpan<byte> bytes)
    {
        _bytes = bytes.ToArray();
    }

    public int Length => _bytes.Length;

    /// <summary>
    /// Deliberately exposes a copy of this binary artifact. The returned array never
    /// aliases the internally retained bytes.
    /// </summary>
    public byte[] ExposeUnchecked() => (byte[])_bytes.Clone();

    public string ToHexString() => Convert.ToHexString(_bytes);

    public bool Equals(BinaryArtifact? other) =>
        other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);

    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is BinaryArtifact other && Equals(other);

    public override int GetHashCode()
    {
        HashCode hash = new();
        foreach (byte value in _bytes)
        {
            hash.Add(value);
        }

        return hash.ToHashCode();
    }

    public override string ToString() => "[binary artifact]";
}
