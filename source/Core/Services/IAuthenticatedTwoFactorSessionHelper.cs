namespace IdentityServer3.Core.Services
{
    public interface IAuthenticatedTwoFactorSessionHelper
    {
        string Create(string subjectId);

        bool Validate(string subjectId, string incomingTWoFactorToken);
    }
}