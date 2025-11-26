using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

/// <summary>
/// US Social Security Number in the form AAA-GG-SSSS.
/// Disallows 000 / 666 / 9xx prefixes, 00 group, and 0000 serial.
/// </summary>
public sealed class SSN : RegexString<SSN>, ICreatable<SSN, string>
{
   public static SSN CreateNonValidated(string valueToWrap)
   {
      return new SSN
      {
         Value = valueToWrap,
         Bounds = _Bounds(11, 11), // "AAA-GG-SSSS"
         Pattern =
            @"^(?!000)(?!666)(?!9\d\d)\d{3}-" +
            @"(?!00)\d{2}-" +
            @"(?!0000)\d{4}$",
         RegexOptions = RegexOptions.CultureInvariant
      };
   }

   protected override bool ExtraValidation() => true;
}
