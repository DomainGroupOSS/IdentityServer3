using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Core.Services
{
    public class DefaultTwoFactorService : ITwoFactorService
    {
        public Task RequestCodeAsync(Client client, ClaimsPrincipal subject)
        {
            return Task.FromResult(0);
        }

        public Task ReSendCodeAsync(Client client, ClaimsPrincipal subject)
        {
            return Task.FromResult(0);
        }

        public Task SendCodeAsync(Client client, ClaimsPrincipal subject)
        {
            return Task.FromResult(0);
        }

        public Task<bool> ShouldChallengeAsync(Client client, ClaimsPrincipal subject,
            IEnumerable<string> scopes)
        {
            if (client == null) throw new ArgumentNullException("client");
            if (subject == null) throw new ArgumentNullException("subject");

            return Task.FromResult(false);
        }

        public Task<bool> VerifyCodeAsync(Client client, ClaimsPrincipal subject, string code)
        {
            return Task.FromResult(true);
        }
    }
}