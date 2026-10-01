#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

/// <summary>Immutable runtime set of authorization scope types.</summary>
public sealed class AuthorizationScopeSet : IEquatable<AuthorizationScopeSet>
{
    private readonly HashSet<Type> _scopes;

    private AuthorizationScopeSet(IEnumerable<Type> scopes)
    {
        _scopes = new HashSet<Type>(scopes);
        if (_scopes.Any(static scope => !typeof(IAuthorizationScope).IsAssignableFrom(scope)))
        {
            throw new ArgumentException("Every authorization scope must implement IAuthorizationScope.", nameof(scopes));
        }
    }

    public static AuthorizationScopeSet Empty { get; } = new(Array.Empty<Type>());

    public static AuthorizationScopeSet Of<TFirst>() where TFirst : IAuthorizationScope =>
        new([typeof(TFirst)]);

    public static AuthorizationScopeSet Of<TFirst, TSecond>()
        where TFirst : IAuthorizationScope
        where TSecond : IAuthorizationScope => new([typeof(TFirst), typeof(TSecond)]);

    public static AuthorizationScopeSet Of<TFirst, TSecond, TThird>()
        where TFirst : IAuthorizationScope
        where TSecond : IAuthorizationScope
        where TThird : IAuthorizationScope => new([typeof(TFirst), typeof(TSecond), typeof(TThird)]);

    public bool ContainsAll(AuthorizationScopeSet required) =>
        required is not null && required._scopes.All(_scopes.Contains);

    public bool Equals(AuthorizationScopeSet? other) =>
        other is not null && _scopes.SetEquals(other._scopes);

    public override bool Equals(object? obj) => obj is AuthorizationScopeSet other && Equals(other);

    public override int GetHashCode() => _scopes.Aggregate(0, static (hash, scope) => HashCode.Combine(hash, scope));
}
