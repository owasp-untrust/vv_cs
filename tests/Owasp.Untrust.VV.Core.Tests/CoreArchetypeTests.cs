using Owasp.Untrust.VV.Core;
using Xunit;

namespace Owasp.Untrust.VV.Core.Tests;

/// <summary>Regression coverage for the replacement built-in value types.</summary>
public sealed class CoreArchetypeTests
{
    [Fact]
    public void Built_in_string_values_use_the_string_traits_pipeline()
    {
        Username username = Username.Parse("Yariv_42", null);
        EmailAddress email = EmailAddress.Parse("alice@example.test", null);

        Assert.Equal("Yariv_42", username.ExposeUnchecked());
        Assert.Equal("alice@example.test", email.ExposeUnchecked());
        Assert.False(Username.TryParse(string.Empty, null, out _));
        Assert.False(EmailAddress.TryParse("not-an-email", null, out _));
    }

    [Fact]
    public void Sensitive_built_in_values_validate_their_expected_format()
    {
        Assert.True(SSN.TryParse("123-45-6789", null, out _));
        Assert.False(SSN.TryParse("123456789", null, out _));
        Assert.True(CreditCard.TryParse("4111111111111111", null, out _));
        Assert.False(CreditCard.TryParse("not-a-card", null, out _));
    }
}
