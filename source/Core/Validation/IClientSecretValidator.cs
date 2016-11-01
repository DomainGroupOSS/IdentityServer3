using System.Threading.Tasks;

namespace IdentityServer3.Core.Validation
{
    internal interface IClientSecretValidator
    {
        Task<ClientSecretValidationResult> ValidateAsync();
    }
}