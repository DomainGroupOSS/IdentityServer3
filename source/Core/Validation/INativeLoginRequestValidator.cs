using System.Collections.Specialized;
using System.Threading.Tasks;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Core.Validation
{
    internal interface INativeLoginRequestValidator
    {
        ValidatedNativeLoginRequest ValidatedRequest { get; }
        Task<NativeLoginRequestValidationResult> ValidateRequestAsync(NameValueCollection parameters, Client client);
    }
}