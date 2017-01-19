using System.Collections.Specialized;
using IdentityServer3.Core;

namespace IdentityServer3.Tests.TokenClients.Setup
{
    public class RefreshTokenTestParameters : NameValueCollection
    {
        public RefreshTokenTestParameters()
        {
            Add(Constants.TokenRequest.RefreshToken, "valid-example-of-refresh-token");
            Add(Constants.TokenRequest.GrantType, Constants.GrantTypes.RefreshToken);
            Add(Constants.NativeLoginRequest.Connect, Constants.NativeLoginRequest.ConnectTypes.NativeLogin);
        }

        public void RemoveRefreshToken()
        {
            Remove(Constants.TokenRequest.RefreshToken);
        }
        public void ChangeToLongRefreshToken()
        {
            RemoveRefreshToken();
            Add(Constants.TokenRequest.RefreshToken, "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii");
        }

        public void ChangeToInvalidRefreshToken()
        {
            RemoveRefreshToken();
            Add(Constants.TokenRequest.RefreshToken, "wwwrrrrroooonnngggg-refresh-token");
        }
    }
}