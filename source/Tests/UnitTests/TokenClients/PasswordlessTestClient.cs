using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Tests.TokenClients
{
    public class PasswordlessTestClient : Client
    {
        public PasswordlessTestClient()
        {
            AllowedCustomGrantTypes.Add(Constants.GrantTypes.DomainNative);
            AllowedCustomGrantTypes.Add(Constants.GrantTypes.Passwordless);
            AllowedScopes.Add(StandardScopes.Profile.Name);
            ClientId = "test-client";
        }

        public void DisableLocalLogin()
        {
            EnableLocalLogin = false;
        }

        public void UnauthorizeDomainNativeGrantType()
        {
            AllowedCustomGrantTypes.Remove(Constants.GrantTypes.DomainNative);
        }
    }
}