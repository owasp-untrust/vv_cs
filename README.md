# OWASP Untrust Validated Values for .NET — v2 design

`vv2_cs` is a secure-by-construction validated-value library for .NET 8. It uses
the sibling `ValueDescriptors_cs` package for shared public-representation and
disclosure-policy contracts. A
validated value is immutable, can only be created through `Parse`/`TryParse`,
and must select an explicit public-disclosure policy.

## Defining a value

```csharp
public sealed class ProjectSlug
    : RegexString<ProjectSlug, Public<string>>,
      IRegexStringDefinition,
      IParsable<ProjectSlug>
{
    private ProjectSlug(string raw, IFormatProvider? provider) : base(raw, provider) { }

    public static Bounds<int> LengthBounds => new(3, 40);
    public static string Pattern => "[a-z][a-z0-9-]*";
    public static RegexOptions Options => RegexOptions.None;
    public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);
    public static string? Format => null;
    public static string Normalize(string value) => value.ToLowerInvariant();
    public static ValidationIssue? ValidateAdditional(string value) => null;

    public static ProjectSlug Parse(string raw, IFormatProvider? provider) => new(raw, provider);

    public static bool TryParse(
        string? raw,
        IFormatProvider? provider,
        out ProjectSlug? result) =>
        TryParseCore(raw, provider, static (value, format) => new(value, format), out result);
}
```

Use `RedactedPii<T>`, `MaskedPii<T,TMasker>`, or `RedactedSecret<T>` instead of
`Public<T>` when the value must not be rendered directly. `ToString()`, logging,
and the ASP.NET JSON converter use the selected safe representation. Raw access
is deliberately conspicuous:

```csharp
string primitive = slug.ExposeUnchecked();
```

There is no `.Value`, public constructor, object initializer, implicit primitive
conversion, or non-validating factory.

Validation shape is type-level rather than instance metadata. String lengths,
numeric bounds, regex patterns, and wire formats are exposed only by archetypes
that support those capabilities. `IValidatedValue` does not contain an extensible
metadata property, and values do not store or copy OpenAPI information.

## Reusable validation traits

Traits package the complete local sequence: parse, normalize, validate, then
additional validation. The library owns that order. A manual leaf inherits
`Parse`/`TryParse` and implements only its inaccessible construction hook:

```csharp
public sealed class Email
    : ValidatedBoundedStringFromTraits<Email, EmailTraits, RedactedPii<string>>,
      IValidatedValueFactory<Email, string>
{
    private Email(string value) : base(value) { }

    static Email IValidatedValueFactory<Email, string>.CreateValidated(string value) =>
        new(value);
}
```

For human-authored values the bundled source generator removes that boilerplate:

```csharp
[ValidatedFromTraits<EmailTraits>]
public sealed partial class Email
{
}
```

Generated traits must select an enforced contract. `IBoundedStringTraits`
requires one `LengthBounds`, checked both before parsing and after normalization.
`IRegexStringTraits` additionally requires and enforces a whitelist expression,
options, and finite timeout. `IBoundedValueTraits` requires
`RawInputLengthBounds` for serialized input and `ValueBounds` for the parsed
number, date, or other ordered value. Parsing, normalization, and additional
validation are mandatory trait members; returning `null` is an explicit decision.

`ISingleLineTextTraits` and `IMultilineTextTraits` force the leaf to declare its
length bounds and its tab, Unicode `OtherSymbol`, and path-safety policies. Their
archetypes reject malformed UTF-16 and disallowed Unicode categories, normalize
text to NFC, and enforce the bounds again afterward. Multiline text additionally
canonicalizes line endings; single-line text rejects them. A trait's
`ValidateAdditional` implementation runs only after these checks, so it can add
restrictions but cannot weaken the archetype. Reusable restrictions such as
`NoLeadingOrTrailingWhitespace`, `NoRepeatedWhitespace`, and
`NoPathSeparators` can be combined with `AllOf<TFirst, TSecond>`.

Generated leaves must be top-level, sealed, partial classes without another base
class. The explicit manual form remains available for generated application code
and tooling. OpenAPI merely observes enforced capabilities and is not part of the
validation path.

Cross-validation candidates use the same traits directly. They retain the
locally validated primitive privately and do not wrap another validated-value
object or expose a raw-value escape hatch.

## Authorized entity resolution

Entity IDs can use `EntityResolutionCandidate` when loading an entity must never
be separated from authorization. A candidate retains its locally validated ID
privately, asks an `IEntityRepository<TId,TEntity>` for the stored entity, and
returns an operation-specific `AuthorizedEntity<TEntity,TOperation>` only after
authorization succeeds.

The built-in grant path uses `ScopedSubjectId<TId,TScope>` values. Both the
authenticated subject and the stored entity provide scoped IDs, while the
library owns the exact intersection check. `IEntityAccessGrants` receives the
typed operation, so shared readers and editors can differ without reducing the
rule to one owner ID. More complex ACL rules use the deliberately separate
`ResolveUsingExplicitAuthorizationPolicyAsync` path.

```csharp
AuthorizedEntity<Document, UpdateDocument> document =
    await documentId.ResolveUpdateAsync(repository, subject, grants, cancellationToken);

await documentService.UpdateAsync(document, request, cancellationToken);
```

Application services should accept the authorized wrapper rather than a bare
entity. This makes operation mismatches and omitted entity authorization type
errors. `HideEntityExistence` maps both missing and forbidden entities to the
same safe not-found failure; `RevealEntityForbidden` is an explicit alternative.
Candidates and authorization evidence cannot cross JSON boundaries.

## ASP.NET Core

Scalar route, query, header, and form binding uses `IParsable<T>` directly.
Register body JSON, `Optional<T>`, safe response serialization, and OpenAPI
metadata once:

```csharp
builder.Services.AddValidatedValues();
```

The integration rejects cross-validation candidates on output and rejects
cross-validated receivers on input.

## Contextual validation and sensitive lifecycles

- `CrossValidationCandidate` performs local parsing only. A domain-specific
  async method performs repository, authorization, DNS, or service checks and
  returns a distinct `CrossValidatedValue` receiver.
- Hashing, authenticated encryption, tokenization, and secret storage use
  application-provided async services.
- Transformed-only values physically retain no plaintext; retained variants
  declare plaintext retention in their type.
- Mutable cryptographic byte buffers are copied on input and output.

## Migration from v1

| v1 | v2 |
|---|---|
| `Wrap` / `From` | `Parse` |
| `TryWrap` / `TryFrom` | `TryParse` |
| `.Value` | `.ExposeUnchecked()` |
| `CreateNonValidated` | Removed |
| `init` bounds/patterns | Static definition members |

This is intentionally a breaking design; unsafe compatibility shims are not
provided.

## Projects

- `Owasp.Untrust.ValueDescriptors`: shared descriptor and disclosure contracts.
- `Owasp.Untrust.VV`: validation core, archetypes, sensitivity, and cross-validation.
- `Owasp.Untrust.VV.AspNetCore`: JSON and Swagger integration.
- `Owasp.Untrust.VV.Analyzers`: security rules `VV2001`–`VV2007`, wired into the core build as errors.
- `Owasp.Untrust.VV.Tests`: runtime and integration tests.

Build and test on Windows:

```powershell
dotnet build Owasp.Untrust.VV.sln
dotnet test tests/Owasp.Untrust.VV.Tests/Owasp.Untrust.VV.Tests.csproj
```
