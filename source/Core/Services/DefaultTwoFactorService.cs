using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Core.Services
{
    public interface ITwoFactorService
    {
        Task<bool> RequiresTwoFactorAsync(Client client, ClaimsPrincipal subject);
    }

    public class DefaultTwoFactorService : ITwoFactorService
    {
        public Task<bool> RequiresTwoFactorAsync(Client client, ClaimsPrincipal subject)
        {
            if (client == null) throw new ArgumentNullException("client");
            if (subject == null) throw new ArgumentNullException("subject");

            return Task.FromResult(true);
        }
    }
}
