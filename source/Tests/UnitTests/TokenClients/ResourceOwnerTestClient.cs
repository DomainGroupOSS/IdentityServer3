using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Tests.TokenClients
{
    public class ResourceOwnerTestClient : Client
    {
        public ResourceOwnerTestClient()
        {
            AllowedCustomGrantTypes.Add(Constants.GrantTypes.DomainNative);
            AllowedCustomGrantTypes.Add(Constants.GrantTypes.Password);
            AllowedScopes.Add("read");
            ClientId = "test-client";
        }
        
        public void DisableLocalLogin()
        {
            EnableLocalLogin = false;
        }

        public void RemoveDomainNative()
        {
            AllowedCustomGrantTypes.Remove(Constants.GrantTypes.DomainNative);
        }
    }
}