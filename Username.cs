using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

public sealed class Username : RegexString<Username>, ICreatable<Username, string>
{
   public static Username CreateNonValidated(string valueToWrap)
   {
      return new Username
      {
         Value = valueToWrap,
         Bounds = _Bounds(3, 32),
         Pattern = @"^[A-Za-z_][A-Za-z0-9_]*$",
         RegexOptions = RegexOptions.CultureInvariant
      };
   }

   protected override bool ExtraValidation() => true;
}
