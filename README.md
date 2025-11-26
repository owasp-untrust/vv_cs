# ValidatedValues (VV)

**Untrust.ValidatedValues (Untrust.VV)** is a small C# library for modeling *validated domain values* as explicit types instead of relying on scattered data annotations and ad-hoc checks.

Instead of:

```csharp
public class PasswordInfoDto
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
public record PasswordInfo(PasswordLength length, Optional<PasswordChars> chars);
```

where `PasswordLength` and `PasswordChars` are *validated* types, and `Optional<T>` encodes optionality at the type level. (see code samples)

---

## Why use VV instead of only annotations?

### Reusable validation

Validation logic lives in *types*, not individual properties:

- A single `PasswordLength` type encapsulates “1–10 characters” once.
- A single `PasswordChars` type encapsulates “distinct printable characters, length 10–256” once.
- A single `Email` / `Phone` / `CreditCard` type encapsulates their respective format rules once.
- Any DTO or entity using these types automatically gets the same validation.

### Stronger assurances via the type system

- Using `PasswordLength` instead of `int` means “this value has already been validated”.
- Using `Email` instead of `string` means “this is a valid email”.
- You can’t accidentally pass an unvalidated primitive where a validated value is required.
- Optionality is explicit through `Optional<T>` rather than “null sometimes means missing”.

### Flexible logic (not limited to attributes)

- Validation is regular C# code, not restricted to attribute shapes.
- You can combine:
  - Bounds (length / range) via `Bounds<T>`
  - Regex checks
  - Content rules (distinctness, character classes, etc.)
  - Domain-specific logic inside `ExtraValidation`.

### Enforced bounds

The bounded base types require a `Bounds` object:

- You must specify min/max bounds for strings and numbers when using the bounded base classes.
- This makes it harder to accidentally forget limits on untrusted input.

### Secure defaults

- **Required by default**: VV types are treated as required unless wrapped in `Optional<T>`.
- **Null only when explicit**: `null` is possible only when:
  - you use `Optional<T>`, or
  - you use nullable reference types explicitly (`T?`).
- This aligns with secure coding practices for untrusted input.

### Framework integration

The library is designed to plug into common .NET infrastructure:

- JSON: a `JsonConverterFactory` makes VV types serialize as their primitive counterparts.
- Swagger / OpenAPI: schema filters map VV types to appropriate primitive schemas, including correct `nullable` for `Optional<T>`.

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
using PwdGen.Contracts;
using PwdGen.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services
   .AddControllers();

builder.Services.AddValidatedValues(); // JSON converters + Swagger schema filters :contentReference[oaicite:1]{index=1}

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<PwdGenerationService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
   app.UseSwagger();
   app.UseSwaggerUI();
}

app.MapPost("/pwd", (PasswordInfo info, PwdGenerationService svc) =>
{
   string password = svc.GeneratePassword(
      info.chars.HasValue ? info.chars.NonNull.Value : null,
      info.length.Value);
   return password;
})
.WithName("Pwd")
.WithOpenApi();

app.MapControllers();

app.Run();
```

That’s all you need: VV plugs into JSON and Swagger automatically.

---

## Concrete validated types (out of the box)

The library ships with several ready-made validated types you can use immediately.

### Email

`Email` wraps a string with bounds and `[EmailAddress]` validation. :contentReference[oaicite:5]{index=5}

```csharp
using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Build;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV;

public class Email : BoundedString<Email>, ICreatable<Email, string>
{
   public static Email CreateNonValidated(string valueToWrap)
   {
      return new Email { Value = valueToWrap, Bounds = _Bounds(3, 256) };
   }

   protected override bool ExtraValidation()
   {
      return new EmailAddressAttribute().IsValid(Value);
   }
}
```

### Phone

`Phone` wraps a string with bounds and `[Phone]` validation. :contentReference[oaicite:6]{index=6}

```csharp
using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Build;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV;

public class Phone : BoundedString<Phone>, ICreatable<Phone, string>
{
   public static Phone CreateNonValidated(string valueToWrap)
   {
      return new Phone { Value = valueToWrap, Bounds = _Bounds(3, 256) };
   }

   protected override bool ExtraValidation()
   {
      return new PhoneAttribute().IsValid(Value);
   }
}
```

### CreditCard

`CreditCard` wraps a string with bounds and `[CreditCard]` validation. :contentReference[oaicite:7]{index=7}

```csharp
using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Build;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV;

public class CreditCard : BoundedString<CreditCard>, ICreatable<CreditCard, string>
{
   public static CreditCard CreateNonValidated(string valueToWrap)
   {
      return new CreditCard { Value = valueToWrap, Bounds = _Bounds(3, 256) };
   }

   protected override bool ExtraValidation()
   {
      return new CreditCardAttribute().IsValid(Value);
   }
}
```

You can use these directly in your request/response models and services:

```csharp
public record ContactInfo(Email email, Optional<Phone> phone);
public record PaymentInfo(CreditCard cardNumber);
```

VV will ensure that wherever an `Email`, `Phone`, or `CreditCard` exists, it has passed its respective validation.

---

## Example: Password generator API

Using the built-in password types in Minimal APIs and controllers.

### Minimal API usage

`PasswordInfo` is used directly as the request body; `Optional<PasswordChars>` is unwrapped safely: :contentReference[oaicite:8]{index=8}

```csharp
app.MapPost("/pwd", (PasswordInfo info, PwdGenerationService svc) =>
{
   string password = svc.GeneratePassword(
      info.chars.HasValue ? info.chars.NonNull.Value : null,
      info.length.Value);
   return password;
})
.WithName("Pwd")
.WithOpenApi();
```

### Controller usage with query parameters

Validated values also work as query-bound parameters:

```csharp
[ApiController]
[Route("[controller]")]
public class PasswordController : ControllerBase
{
   [HttpGet("pwdg")]
   public IActionResult GenPwd([FromQuery] PasswordLength length, PwdGenerationService svc)
   {
      var pwd = svc.GeneratePassword(null, length.Value);
      return Ok(pwd);
   }
}
```

---

## Core building blocks (with source examples)

### `BoundedNumber<TWrapper, ValueT>`

Base class for numeric validated values with min/max range. :contentReference[oaicite:9]{index=9}

```csharp
using System.Numerics;

using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Build;

public abstract class BoundedNumber<TWrapper, ValueT> : ValidatedValue<TWrapper, ValueT, SelfParsableAdapter<ValueT>>
   where TWrapper : BoundedNumber<TWrapper, ValueT>, ICreatable<TWrapper, ValueT>
   where ValueT : INumber<ValueT>
{
   protected static Bounds<ValueT> _Bounds(ValueT min, ValueT max) { return new Bounds<ValueT>(min, max); }
   public required Bounds<ValueT> Bounds { get; init; }

   protected override ValidationResultHolder ChainableValidation()
   {
      ValidationResultHolder result = base.ChainableValidation();
      if (Value < Bounds.Min || Value > Bounds.Max)
      {
         result.Invalidate();
      }
      return result;
   }
}
```

### `BoundedString<TWrapper>`

Base class for string validated values with length bounds. :contentReference[oaicite:10]{index=10}

```csharp
using System.Numerics;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Build;

public abstract class BoundedString<TWrapper> : ValidatedValue<TWrapper, string, SelfParsableAdapter<string>>
   where TWrapper : BoundedString<TWrapper>, ICreatable<TWrapper, string>
{
   protected static Bounds<int> _Bounds(int minLength, int maxLength) { return new Bounds<int>(minLength, maxLength); }
   public required Bounds<int> Bounds { get; init; }

   protected override ValidationResultHolder ChainableValidation()
   {
      ValidationResultHolder result = base.ChainableValidation();
      if (Value.Length < Bounds.Min || Value.Length > Bounds.Max)
      {
         result.Invalidate();
      }
      return result;
   }
}
```

### `RegexString<TWrapper>`

Bounded string + regex, with safe timeout and optional compilation. :contentReference[oaicite:11]{index=11}

```csharp
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Build;

public abstract class RegexString<TWrapper> : BoundedString<TWrapper>
   where TWrapper : RegexString<TWrapper>, ICreatable<TWrapper, string>
{
   public required string Pattern { get; init; }

   // Regex options for this wrapper type
   public RegexOptions RegexOptions { get; init; } = RegexOptions.None;
   public TimeSpan Timeout { get; init; } = new TimeSpan(1_000_000); // 100ms
    
   // Shared cache of compiled regexes, keyed by wrapper type
   private static readonly ConcurrentDictionary<Type, Regex> _compiledRegexCache = new();

   private Regex GetRegex()
   {
      var options = RegexOptions;

      // If not compiled, just create a fresh Regex (cheap for occasional use)
      if ((options & RegexOptions.Compiled) == 0)
      {
         return new Regex(Pattern, options, Timeout);
      }

      // Compiled: cache per TWrapper
      var key = typeof(TWrapper);
      return _compiledRegexCache.GetOrAdd(
         key,
         _ => new Regex(Pattern, options, Timeout)
      );
   }

   protected override ValidationResultHolder ChainableValidation() {
      var result = base.ChainableValidation();
      if (!result.IsValid) {
         return result;
      }
      Debug.Assert(Value != null);

      var regex = GetRegex();
      if (!regex.IsMatch(Value))
      {
         result.Invalidate();
      }

      return result;
   }
}
```

### `SingleWord<TWrapper>`

A bounded string restricted to ASCII letters (a–z / A–Z). :contentReference[oaicite:13]{index=13}

```csharp
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Build;

public abstract class SingleWord<TWrapper> : BoundedString<TWrapper>
   where TWrapper : SingleWord<TWrapper>, ICreatable<TWrapper, string>
{
   protected override ValidationResultHolder ChainableValidation()
   {
      ValidationResultHolder result = base.ChainableValidation();
      foreach (char c in Value.ToCharArray())
      {
         if (!char.IsAsciiLetter(c))
         {
            result.Invalidate();
            break;
         }
      }
      return result;
   }
}
```

### `Distinct<TValue>` (helper for distinct collections)

Internal helper that carries bounds along with a `HashSet<TValue>`. :contentReference[oaicite:14]{index=14}

```csharp
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Build;

class Distinct<TValue> : HashSet<TValue>
{
   protected static Bounds<int> _Bounds(int minLength, int maxLength) { return new Bounds<int>(minLength, maxLength); }
   public required Bounds<int> Bounds { get; init; }
}
```

### `WithDuplicates<TValue>` (data-annotations example)

Example of using `IValidatableObject` + bounds for collection size. :contentReference[oaicite:15]{index=15}

```csharp
using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Build;

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
```

---

## Defining your own validated types

### 1. Using `BoundedNumber`

Typical pattern:

```csharp
public sealed class Age : BoundedNumber<Age, int>, ICreatable<Age, int>
{
   public static Age CreateNonValidated(int valueToWrap)
   {
      return new Age { Value = valueToWrap, Bounds = _Bounds(0, 130) };
   }

   protected override bool ExtraValidation() => true; // or your custom logic
}
```

**PasswordLength** – bounded integer, 1–10. :contentReference[oaicite:2]{index=2}

```csharp
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Build;

namespace PwdGen.Contracts;

public class PasswordLength : BoundedNumber<PasswordLength, int>, ICreatable<PasswordLength, int>
{
   public static PasswordLength CreateNonValidated(int valueToWrap)
   {
      return new PasswordLength { Value = valueToWrap, Bounds = _Bounds(1, 10) };
   }

   protected override bool ExtraValidation() { return true; }
}
```

### 2. Using `RegexString`

For structured strings (emails, slugs, IDs), you can:

- Inherit from `RegexString<TWrapper>`
- Provide a `Pattern`, `RegexOptions`, and `Bounds`

You already do something similar with `DistinctPrintableChars<TWrapper>` for password characters.


### 3. Using `ValidatedValue` directly

For more complex cases:

- Inherit from `ValidatedValue<TWrapper, ValueT, ParserT>`
- Implement:
  - `ExtraValidation` for domain-specific checks
  - Any additional properties/methods you need
- Optionally define intermediate abstract base classes (like `BoundedString`) for reuse.

---

## Defining your own building blocks

If you see a recurring pattern across multiple VV types:

- Create an abstract base (e.g. `NonEmptyLowercaseString<TWrapper> : RegexString<TWrapper>`)
- Encapsulate:
  - A specific regex
  - Bounds
  - Shared validation behavior

Then concrete types in that family only need to:

- Set their specific bounds (if different)
- Possibly override `ExtraValidation` for additional rules

This layered approach is how `BoundedString`, `RegexString`, `DistinctPrintableChars`, and `SingleWord` are built and reused across multiple domain types.

Here's an example of defining `DistinctPrintableChars` - a building-block class later used to create a `PasswordChars` validated values type:

```csharp contracts/in/buildblocks/DistinctPrintableChars.cs
using Owasp.Untrust.VV.Build;
using Owasp.Untrust.VV.Core;

namespace PwdGen.Contracts.In.Build;

public abstract class DistinctPrintableChars<TWrapper> : BoundedString<TWrapper>
    where TWrapper : DistinctPrintableChars<TWrapper>, ICreatable<TWrapper, string>
{
    protected override ValidationResultHolder ChainableValidation()
    {
        ValidationResultHolder result = base.ChainableValidation();
        if (Value.Distinct().Count() != Value.Length)
        {
                result.Invalidate();
        }
        else
        {
            foreach (char c in Value.ToCharArray())
            {
                if (char.IsControl(c) || char.IsHighSurrogate(c) || char.IsLowSurrogate(c))
                {
                    result.Invalidate();
                    break;
                }
            }
        }
        return result;
    }
}
```

After the building block is defined, it can be used to create validated value types, in this case a `PasswordChars` class for 8–64 distinct printable characters :contentReference[oaicite:3]{index=3}

```csharp
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Build;

public class PasswordChars : DistinctPrintableChars<PasswordChars>, ICreatable<PasswordChars, string>
{
   public static PasswordChars CreateNonValidated(string valueToWrap)
   {
      return new PasswordChars { Value = valueToWrap, Bounds = _Bounds(8, 64) };
   }

   protected override bool ExtraValidation()
   {
      return true;
   }
}
```
