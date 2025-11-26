using System.Net;
using System.Net.Sockets;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV;

public class IP<TIpPolicy>
   : ValidatedValue<IP<TIpPolicy>, IPAddress, SelfParsableAdapter<IPAddress>>, ICreatable<IP<TIpPolicy>, IPAddress>
   where TIpPolicy : IpAddressPolicy
{
    public static IP<TIpPolicy> CreateNonValidated(IPAddress valueToWrap)
    {
        return new IP<TIpPolicy> { Value = valueToWrap };
    }

    protected override bool ExtraValidation() => true;

    protected override ValidationResultHolder ChainableValidation() { 
        var result = new ValidationResultHolder(true);
        if (!TIpPolicy.MatchesPolicy(Value))
        {
            result.Invalidate();
        }

        return result;
    }
}
