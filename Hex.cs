using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

/// <summary>
/// General-purpose hex value (1–32 hex digits, no 0x prefix).
/// </summary>
public sealed class Hex : HexString<Hex>, ICreatable<Hex, string>
{
   public static Hex CreateNonValidated(string valueToWrap)
   {
      return new Hex
      {
         Value = valueToWrap,
         // up to 2048 bits (512 hex digits) – adjust as needed
         Bounds = _Bounds(1, 512)         
      };
   }

   protected override bool ExtraValidation() => true;
}