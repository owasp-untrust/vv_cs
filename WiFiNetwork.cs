using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

/// <summary>
/// Wi-Fi SSID: 1–32 printable ASCII characters, no control characters.
/// </summary>
public sealed class WiFiNetwork : RegexString<WiFiNetwork>, ICreatable<WiFiNetwork, string>
{
   public static WiFiNetwork CreateNonValidated(string valueToWrap)
   {
      return new WiFiNetwork
      {
         Value = valueToWrap,
         Bounds = _Bounds(1, 32),
         Pattern = @"^[\x20-\x7E]+$", // space to '~'
         RegexOptions = RegexOptions.CultureInvariant
      };
   }

   protected override bool ExtraValidation() => true;
}
