using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Core.Services
{
    /// <summary>
    /// Service to manage two factor actions
    /// </summary>
    public interface ITwoFactorService
    {
        Task<bool> ShouldChallengeAsync(Client client, ClaimsPrincipal subject, IEnumerable<string> scopes);

        Task SendCodeAsync(Client client, ClaimsPrincipal subject);

        Task RequestCodeAsync(Client client, ClaimsPrincipal subject);

        Task ReSendCodeAsync(Client client, ClaimsPrincipal subject);

        Task<bool> VerifyCodeAsync(Client client, ClaimsPrincipal subject, string code);
    }
}