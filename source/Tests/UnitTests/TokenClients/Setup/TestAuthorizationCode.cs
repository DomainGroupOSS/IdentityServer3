using System;
using System.Collections.Generic;
using System.Security.Claims;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Tests.TokenClients.Setup
{
    public class TestAuthorizationCode : AuthorizationCode
    {
        public TestAuthorizationCode(Client client)
        {
            Client = client;
            CodeChallenge = "bacon-ipsum-dolor-amet-cupim-pork-belly-flank-kielbasa-fatback-t-bone-ham-hock-shankle-pancetta".Sha256();
            CodeChallengeMethod = Constants.CodeChallengeMethods.Plain;
            CreationTime = DateTimeOffset.Now;
            RedirectUri = "https://test.domain.com.au";
            RequestedScopes = new List<Scope>()
            {
                new Scope
                {
                    Name = "read"
                },
                new Scope
                {
                    Name = "write"
                }
            };
            Subject = new ClaimsPrincipal()
            {
                
            };
        }

        public void SetToWrongCodeChallenge()
        {
            CodeChallenge = "lorem-ipsum-dolor-amet-cupim-pork-belly-flank-kielbasa-fatback-t-bone-ham-hock-shankle-pancetta".Sha256();
        }

        public void RemoveCodeChallenge()
        {
            CodeChallenge = null;
        }

        public void RemoveCodeChallengeMethod()
        {
            CodeChallengeMethod = null;
        }

        public void SetCodeChallengeMethodToRandom()
        {
            CodeChallengeMethod = "test-invalid-code-challenge-method";
        }

        public void SetCodeChallengeMethodToSha256()
        {
            CodeChallengeMethod = Constants.CodeChallengeMethods.SHA_256;
        }

        public void SetToOldCreationtime()
        {
            CreationTime = new DateTimeOffset(DateTime.Now.AddHours(-1));
        }

        public void RemoveDefaultRequestedScopes()
        {
            RequestedScopes = null;
        }
    }
}