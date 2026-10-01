# StringPreprocessing

Prototype implementation of a statically structured preprocessing chain.

## Properties

- `StringTraits<TPreprocessing>` exposes normalization and validation operations.
- A preprocessing step may implement:
  - `IStringNormalizer`
  - `ICharactersValidator`
  - `IStringValidator`
  - any combination of the above.
- The chain leaf must contain a step implementing `ICharactersValidator`.
- Normalizers execute in reverse chain order.
- Character validators execute in forward chain order.
- String validators execute in forward chain order.
- Chain traversal uses generic static calls rather than linked-list instances.
- Capability selection uses runtime type pattern matching.
- Steps are `struct`s, allowing the JIT to specialize closed generic chains and potentially eliminate interface checks/boxing after inlining.

## Example

```csharp
var traits = ExampleChain.CreateTraits();

string value =
    traits.NormalizeBeforeValidation("hello\r\nworld");

ValidationIssue? issue =
    traits.ValidateCharacters(value) ??
    traits.Validate(value);
```
