using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

/// <summary>
/// Generic IoT device identifier: letters, digits, dash, underscore, colon, and slash.
/// </summary>
public sealed class DeviceId : RegexString<DeviceId>, ICreatable<DeviceId, string>
{
   public static DeviceId CreateNonValidated(string valueToWrap)
   {
      return new DeviceId
      {
         Value = valueToWrap,
         Bounds = _Bounds(8, 64),
         Pattern = @"^[A-Za-z0-9_\-:/]+$",
         RegexOptions = RegexOptions.CultureInvariant
      };
   }

   protected override bool ExtraValidation() => true;
}
