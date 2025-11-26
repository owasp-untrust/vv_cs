using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

public sealed class MacAddress : RegexString<MacAddress>, ICreatable<MacAddress, string>
{
   public static MacAddress CreateNonValidated(string valueToWrap)
   {
      return new MacAddress
      {
         Value = valueToWrap,
         Bounds = _Bounds(17, 17), // "AA:BB:CC:DD:EE:FF"
         Pattern = @"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$",
         RegexOptions = RegexOptions.CultureInvariant | RegexOptions.IgnoreCase
      };
   }

   protected override bool ExtraValidation() => true;
}
