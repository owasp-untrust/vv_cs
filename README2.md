# ValidatedValues (VV)

**Untrust.ValidatedValues (Untrust.VV)** is a small C# library for modeling *validated domain values* as explicit types instead of relying on scattered data annotations and ad-hoc checks.

Instead of:

```csharp
public class PasswordGenerationConfigDTO
{
   [Range(1, 10)]
   public int Length { get; set; }

   [MinLength(10)]
   [MaxLength(256)]
   public string? Chars { get; set; }
}
```

you use:

```csharp
public sealed record PasswordGenerationConfigDTO(
   PasswordLength Length,
   Optional<PasswordChars> Chars);
```

where `PasswordLength` and `PasswordChars` are *validated* types, and `Optional<T>` encodes optionality at the type level. (See the code samples below.)

---

## Why use VV instead of only annotations?

### Reusable validation

Validation logic lives in types, not individual properties:

- A single `PasswordLength` type encapsulates “1–10 characters” once.
- A single `PasswordChars` type encapsulates “distinct printable characters, length 10–256” once.
- A single `Email` or `Phone` or `CreditCard` type encapsulates its format rules once.
- Any DTO or entity using these types automatically gets the same validation.

### Stronger assurances via the type system

- Using `PasswordLength` instead of `int` means “this value has already been validated as a legal length”.
- Using `Email` instead of `string` means “this is a valid email”.
- You cannot accidentally pass an unvalidated primitive where a validated value is required.
- Optionality is explicit through `Optional<T>` rather than “null sometimes means missing”.

### Flexible logic (not limited to attributes)

- Validation is regular C# code, not restricted to attribute shapes.
- You can combine:
  - Bounds (length or numeric range) via `Bounds<T>`
  - Regex checks
  - Content rules (distinctness, character classes, etc.)
  - Domain-specific logic inside `ExtraValidation`.
  - Definition of reusable archetype classes that contain a hook into a validation chain common to all types extending the archetype (via `ChainableValidation`)

### Enforced bounds

The bounded archetypes require a `Bounds` object:

- You must specify min and max bounds for strings and numbers when using the bounded archetypes.
  This makes it harder to forget limits on untrusted input.

### Secure defaults

- Required by default: VV types are treated as required unless wrapped in `Optional<T>`.
- Null only when explicit: `null` is possible only when:
  - you use `Optional<T>`, or
  - you use nullable reference types explicitly (`T?`).

This aligns with secure by default coding practices for untrusted input.

### Framework integration

The library is designed to plug into common .NET infrastructure:

- JSON: a `JsonConverterFactory` makes VV types serialize as their primitive counterparts.
- Swagger / OpenAPI: schema filters map VV types to appropriate primitive schemas, including correct `nullable` for `Optional<T>`.

You configure this once, and then use your validated value types directly in controllers, minimal APIs, and DTOs.

---

## Namespaces

- `Owasp.Untrust.VV.Archetypes`  
  Public surface for defining validated values:
  - Archetypes such as `BoundedNumber<,>`, `BoundedPrintableString<>`, `RegexString<>`, `HexString<>`, `SingleWord<>`
  - Shared helpers such as `Bounds<T>`, `ICreatable<,>`, and `Optional<T>`

- `Owasp.Untrust.VV.Core`  
  Low level infrastructure and hierarchical base classes used to implement archetypes:
  - `BoundedNumberBase<,>`, `BoundedAnyContentStringBase<>`, `RegexStringBase<>`, `HexStringBase<>`, etc.
  - Validation pipeline internals and extension points

When you implement your own validated value (such as `Age`, `Username`, or `DeviceId`), you normally only need:

```csharp
using Owasp.Untrust.VV.Archetypes;
```

---

## Getting started

### 1. Install the package

In your `.csproj`:

```xml
<ItemGroup>
   <PackageReference Include="Owasp.Untrust.VV" Version="x.y.z" />
</ItemGroup>
```

### 2. Register ValidatedValues in `Program.cs`

ValidatedValues integration is a single line in startup: `AddValidatedValues()`.

```csharp
using Microsoft.AspNetCore.Mvc;
using PwdGen.Contracts.In;
using PwdGen.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services
   .AddControllers();


// *** Activate Validated Values (VV) support
// *** JSON converters + Swagger schema filters
builder.Services.AddValidatedValues();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<PwdGenerationService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
   app.UseSwagger();
   app.UseSwaggerUI();
}

// Minimal API usage example
app.MapPost("/pwd", (PasswordGenerationConfigDTO config, PwdGenerationService svc) =>
{
   string? chars = config.Chars.HasValue ? config.Chars.NonNull.Value : null;
   string password = svc.GeneratePassword(chars, config.Length.Value);
   return password;
})
.WithName("Pwd")
.WithOpenApi();

app.MapControllers();

app.Run();
```

That is all you need: VV plugs into JSON and Swagger automatically.

---

## Concrete validated types (out of the box)

The library ships with several ready made validated types you can use immediately.

### Email

`Email` wraps a string with bounds and email format validation (using `EmailAddressAttribute` internally).  
It is implemented as a `BoundedPrintableString<Email>` archetype plus extra validation.

See implementation at:

- `Owasp.Untrust.VV/Email.cs`

### Phone

`Phone` wraps a string with bounds and phone format validation (using `PhoneAttribute` internally).  
It is implemented as a `BoundedAnyContentString<Phone>` archetype plus extra validation that ensure its character are valid for a phone.

See implementation at:

- `Owasp.Untrust.VV/Phone.cs`

### CreditCard

`CreditCard` wraps a string with bounds and credit card format validation (using `CreditCardAttribute` internally).  
It is implemented as a `BoundedAnyContentString<CreditCard>` archetype plus extra validation to ensure its characters are valid for a credit-card.

See implementation at:

- `Owasp.Untrust.VV/CreditCard.cs`

You can use these directly in your request or response models and services:

```csharp
public sealed record ContactDTO(Email Email, Optional<Phone> Phone);

public sealed record PaymentInfoDTO(CreditCard CardNumber, Name NameOnCard, CVV Cvv);
```

Wherever an `Email`, `Phone`, `CreditCard`, `Name` or `CVV` exists, it has passed its respective validation.

---

## Archetypes and helpers

This section gives an overview of the main archetypes. For details, see the corresponding `.cs` files in the repository.

### `Bounds<T>`

Represents an inclusive range of values (for numbers or lengths).  
Used by the bounded archetypes to define allowed ranges.

See implementation at:

- `Owasp.Untrust.VV/Archetypes/Bounds.cs`

### `ICreatable<TWrapper, ValueT>`

Interface implemented by all wrapper types so archetypes and Core can construct them internally:

```csharp
public interface ICreatable<TWrapper, ValueT>
{
   static abstract TWrapper CreateNonValidated(ValueT valueToWrap);
}
```

See implementation at:

- `Owasp.Untrust.VV/Archetypes/ICreatable.cs`

### `BoundedNumber<TWrapper, ValueT>`

Archetype for numeric ranges.

- Use when you want a validated number such as `Age`, `RetryCount`, or `PasswordLength` with a min and max range.
- Constraints:
  - `ValueT` implements `INumber<ValueT>`
  - `TWrapper` implements `ICreatable<TWrapper, ValueT>` and derives from `BoundedNumber<TWrapper, ValueT>`
- Configuration:
  - `Bounds<ValueT> Bounds` (init only) defines the allowed range.

See implementation at:

- `Owasp.Untrust.VV/Archetypes/BoundedNumber.cs`

### `BoundedPrintableString<TWrapper>`

Archetype for strings with length constraints.

- A length-constrained string that can contain anything - only min and max length are validated.
- WARNING: Be careful! The string's content is NOT checked/validated.
- Configuration:
  - `Bounds<int> Bounds` (init only) defines min and max length in characters.

See implementation at:

- `Owasp.Untrust.VV/Archetypes/BoundedString.cs`

### `SingleLine<TWrapper>`
### `Multiline<TWrapper>`

Archetype for strings with length constraints.

- Use when you only care about min and max length, not content pattern.
- Use when you allow any printable character (no control characters, except for tab and maybe newline)
- Newline is allowed only in the *Multiline* version
- Configuration:
  - `Bounds<int> Bounds` (init only) defines min and max length in characters.

See implementation at:

- `Owasp.Untrust.VV/Archetypes/SingleLine.cs`
- `Owasp.Untrust.VV/Archetypes/Multiline.cs`

### `RegexString<TWrapper>`

Archetype for strings validated by both length and regex.

- Use when you need both a length range and a regex constraint.
- Configuration:
  - `Bounds<int> Bounds` (init only)
  - `string Pattern` (init only)
  - *\[optional\]* `RegexOptions RegexOptions` (init only, defaults to `RegexOptions.None`)
  - *\[optional\]* `TimeSpan Timeout` (init only, defaults to 100ms)  
- Regex compilation, caching, options, and timeout are handled in the Core base class.

See implementation at:

- `Owasp.Untrust.VV/Archetypes/RegexString.cs`

### `HexString<TWrapper>`

Archetype for hex encoded values.

- Use when the underlying value is a hex string (IDs, tokens, hashes, etc.).
- Configuration:
  - `Bounds<int> Bounds` (init only) for min and max hex length.
- Behavior:
  - Hex validation is built in at the Core level (canonical hex pattern).
  - Conversion helpers (for example to `int`, `long`, `byte[]`) are provided by the base class.

See implementation at:

- `Owasp.Untrust.VV/Archetypes/HexString.cs`

### `SingleWord<TWrapper>`

Archetype for single ASCII words (letters only).

- Built on top of `RegexString<TWrapper>`.
- Ensures all characters are ASCII letters (a single word, no spaces or punctuation).

See implementation at:

- `Owasp.Untrust.VV/Archetypes/SingleWord.cs`

---

## Example: password generator API

This example shows how to use archetypes to define:

- `PasswordLength` using `BoundedNumber`
- `PasswordChars` using a custom building block based on `BoundedString`
- `PasswordGenerationConfigDTO` as a DTO
- API endpoints that consume these validated values

### Domain type: `PasswordLength` (numeric archetype)

```csharp
// src/PwdGen/Domain/PasswordLength.cs
using Owasp.Untrust.VV.Archetypes;

namespace PwdGen.Contracts.In;

public sealed class PasswordLength
   : BoundedNumber<PasswordLength, int>, ICreatable<PasswordLength, int>
{
   // Accept password lengths between 1 and 10 characters.
   private static readonly Bounds<int> s_bounds = _Bounds(8, 64);

   public static PasswordLength CreateNonValidated(int valueToWrap)
   {
      return new PasswordLength
      {
         Value = valueToWrap,
         Bounds = s_bounds,
      };
   }
}
```

### User defined building block: `DistinctPrintableChars<TWrapper>`

This is a reusable building block for “distinct printable characters” that you define in your own project on top of `BoundedAnyContentStringBase<TWrapper>`.

```csharp
// src/PwdGen/Contracts/In/Build/DistinctPrintableChars.cs
using System.Linq;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;

namespace PwdGen.Contracts.In.Build;

public abstract class DistinctPrintableChars<TWrapper> : BoundedAnyContentStringBase<TWrapper>
   where TWrapper : DistinctPrintableChars<TWrapper>, ICreatable<TWrapper, string>
{
   protected override ValidationResultHolder ChainableValidation()
   {
      ValidationResultHolder result = base.ChainableValidation();
      if (!result.IsValid)
      {
         return result;
      }

      // All characters must be distinct.
      if (Value.Distinct().Count() != Value.Length)
      {
         result.Invalidate();
         return result;
      }

      // No control or surrogate characters.
      foreach (char c in Value)
      {
         if (char.IsControl(c) || char.IsHighSurrogate(c) || char.IsLowSurrogate(c))
         {
            result.Invalidate();
            break;
         }
      }

      return result;
   }
}
```

### Domain type: `PasswordChars` (using the building block)

```csharp
// src/PwdGen/Domain/PasswordChars.cs
using Owasp.Untrust.VV.Archetypes;
using PwdGen.Contracts.In.Build;

namespace PwdGen.Contracts.In;

public sealed class PasswordChars
   : DistinctPrintableChars<PasswordChars>, ICreatable<PasswordChars, string>
{
   // For example, require between 4 and 128 distinct printable characters.
   private static readonly Bounds<int> s_bounds = _Bounds(4, 128);

   public static PasswordChars CreateNonValidated(string valueToWrap)
   {
      return new PasswordChars
      {
         Value = valueToWrap,
         Bounds = s_bounds,
      };
   }
}
```

### DTO: `PasswordGenerationConfigDTO`

```csharp
// src/PwdGen/Contracts/In/PasswordGenerationConfigDTO.cs
using Owasp.Untrust.VV;
using PwdGen.Domain;

namespace PwdGen.Contracts.In;

/// <summary>
/// Input DTO for password generation:
/// - Length: required, validated via PasswordLength
/// - Chars: optional, validated via PasswordChars when present
/// </summary>
public sealed record PasswordGenerationConfigDTO(
   PasswordLength Length,
   Optional<PasswordChars> Chars);
```

### Minimal API usage

`PasswordGenerationConfigDTO` is used directly as the request body. `Optional<PasswordChars>` is unwrapped safely:

```csharp
app.MapPost("/pwd", (PasswordGenerationConfigDTO config, PwdGenerationService svc) =>
{
   string? chars = config.Chars.HasValue ? config.Chars.NonNull.Value : null;
   string password = svc.GeneratePassword(chars, config.Length.Value);
   return password;
})
.WithName("Pwd")
.WithOpenApi();
```

### Controller usage with query parameters

Validated values also work as query bound parameters:

```csharp
[ApiController]
[Route("[controller]")]
public class PasswordController : ControllerBase
{
   [HttpGet("pwdg")]
   public IActionResult GenPwd([FromQuery] PasswordLength length, PwdGenerationService svc)
   {
      string pwd = svc.GeneratePassword(null, length.Value);
      return Ok(pwd);
   }
}
```

---

## Defining your own validated types

### 1. Using `BoundedNumber`

Typical pattern:

```csharp
using Owasp.Untrust.VV.Archetypes;

public sealed class Age : BoundedNumber<Age, int>, ICreatable<Age, int>
{
   private static readonly Bounds<int> s_bounds = _Bounds(0, 130);

   public static Age CreateNonValidated(int valueToWrap)
   {
      return new Age
      {
         Value = valueToWrap,
         Bounds = s_bounds,
      };
   }
}
```

Key points:

- `Age` is sealed and derives from `BoundedNumber<Age, int>`.
- Bounds are defined once in a static field.
- Validation of value and bounds is handled by the archetype and the Core pipeline.

For additional domain rules (for example, “age must be 18 or above”), you can override the archetype hook (for example `ChainableValidation`) in the same way that `SingleWord<>` and `DistinctPrintableChars<>` do.

### 2. Using `RegexString`

For structured strings such as emails, slugs, IDs, and usernames, you can:

- Inherit from `RegexString<TWrapper>`
- Provide a `Pattern`, `RegexOptions` (through configuration), and `Bounds`

Archetype logic handles:

- Length checks via `Bounds<int>`
- Regex compilation and caching
- Timeout for regex execution

Your type only needs to define the correct pattern and bounds.

---

## Defining your own building blocks

If you see a recurring pattern across multiple validated value types:

- Create an abstract base in your own code (for example `DistinctPrintableChars<TWrapper> : BoundedString<TWrapper>`).
- Encapsulate:
  - A specific regex or character level rule
  - Bounds
  - Shared validation behavior

Then concrete types in that family only need to:

- Set their specific bounds (if they differ)
- Optionally override the hook for more domain specific rules

The `DistinctPrintableChars<TWrapper>` and `PasswordChars` example above follows exactly this pattern:

1. `DistinctPrintableChars<TWrapper>` is a building block based on the `BoundedString` archetype.
2. `PasswordChars` is a validated value that inherits from this building block and fixes its own bounds.

---

## Extending VV with new archetypes (Core)

If the existing archetypes are not enough, you can build your own archetype on top of the Core base classes in `Owasp.Untrust.VV.Core`:

- `BoundedNumberBase<TWrapper, ValueT>`
- `BoundedAnyContentStringBase<TWrapper>`
- `RegexStringBase<TWrapper>`
- `HexStringBase<TWrapper>`

- WARNING: Be careful with the BoundedAnyContentStringBase! The string's content is NOT checked/validated and it COULD contain control characters.

These base classes:

- Expose abstract constraint methods such as `BoundsConstraint()` and `PatternConstraint()`.
- Provide a chainable validation pipeline that archetypes hook into.
- Allow you to add new archetypes that still integrate with JSON converters, Swagger schema filters, and the rest of the VV infrastructure.

Typical flow:

1. Create a new abstract base in Core that overrides the constraint methods and optionally adds extra validation.
2. Optionally add a property style archetype in `Owasp.Untrust.VV.Archetypes` that wraps your base and exposes constraints as init only properties, similar to `BoundedNumber<>` and `RegexString<>`.
3. Have your domain specific validated types derive from your new archetype.

You pick one archetype that best describes the validation pattern.
