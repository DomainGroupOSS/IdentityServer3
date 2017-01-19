using System;
using System.Collections.Generic;
using System.Security.Claims;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Tests.TokenClients.Setup
{
    public class TestRefreshToken : RefreshToken
    {
        public TestRefreshToken(Client client, List<Claim> claims)
        {
            var accessToken = new Token
            {
                Client = client,
                Claims = claims,
            };

            AccessToken = accessToken;
            CreationTime = DateTimeOffset.Now;
            LifeTime = 360;
        }
        public TestRefreshToken(Client client)
        {
            var accessToken = new Token
            {
                Client = client,
                Claims = new List<Claim>
                {
                    new Claim("scope", "read"),
                    new Claim("scope", Constants.StandardScopes.OfflineAccess),
                    new Claim(Constants.ClaimTypes.Subject, "test-subject-id")
                }
            };

            AccessToken = accessToken;
            CreationTime = DateTimeOffset.Now;
            LifeTime = 360;
        }

        public void SetCreationTimeToExpired()
        {
            CreationTime = DateTimeOffset.Now.AddHours(-1);
        }
    }
}