using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Tests.TokenClients
{
    public class RefreshTokenTestClient : Client
    {
        public RefreshTokenTestClient()
        {
            AllowedCustomGrantTypes.Add(Constants.GrantTypes.DomainNative);
            AllowedCustomGrantTypes.Add(Constants.GrantTypes.RefreshToken);
            AllowedScopes.Add("read");
            AllowedScopes.Add(Constants.StandardScopes.OfflineAccess);
            ClientId = "test-client";
        }

        public void RemoveOfflineAccessScope()
        {
            AllowedScopes.Remove(Constants.StandardScopes.OfflineAccess);
        }
    }
}