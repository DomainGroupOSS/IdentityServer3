using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Core.Validation
{
    public interface IScopeValidator
    {
        bool ContainsOpenIdScopes { get; }
        bool ContainsResourceScopes { get; }
        bool ContainsOfflineAccessScope { get; set; }
        List<Scope> RequestedScopes { get; }
        List<Scope> GrantedScopes { get; }
        void SetConsentedScopes(IEnumerable<string> consentedScopes);
        Task<bool> AreScopesValidAsync(IEnumerable<string> requestedScopes);
        bool AreScopesAllowed(Client client, IEnumerable<string> requestedScopes);
        bool IsResponseTypeValid(string responseType);
    }
}