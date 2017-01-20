using System.Collections.Generic;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Tests.TokenClients
{
    public class AuthorizationCodeTestClient : Client
    {
        public AuthorizationCodeTestClient()
        {
            AllowedCustomGrantTypes.Add(Constants.GrantTypes.DomainNative);
            AllowedCustomGrantTypes.Add(Constants.GrantTypes.AuthorizationCode);
            AllowedScopes.Add("read");
            ClientId = "test-client";
            Flow = Flows.ClientCredentials;
            AuthorizationCodeLifetime = 30;
        }

        public void UnauthorizeDomainNativeGrantType()
        {
            AllowedCustomGrantTypes.Remove(Constants.GrantTypes.DomainNative);
        }

        public void SetFlowToAuthorizationCodeWithProofKey()
        {
            Flow = Flows.AuthorizationCodeWithProofKey;
        }

        public void SetFlowToHybridWithProofKey()
        {
            Flow = Flows.HybridWithProofKey;
        }

        public void RemoveAuthorizationCodeFromAllowedGrantType()
        {
            AllowedCustomGrantTypes.Remove(Constants.GrantTypes.AuthorizationCode);
        }
    }
}