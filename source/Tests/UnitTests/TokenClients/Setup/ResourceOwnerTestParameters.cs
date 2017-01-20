using System.Collections.Specialized;
using IdentityServer3.Core;

namespace IdentityServer3.Tests.TokenClients.Setup
{
    public class ResourceOwnerTestParameters : NameValueCollection
    {
        public ResourceOwnerTestParameters()
        {
            Add(Constants.TokenRequest.GrantType, Constants.GrantTypes.Password);
            Add(Constants.TokenRequest.Scope, "read");
            Add(Constants.NativeLoginRequest.ConnectChallenge, "test-connect-code");
            Add(Constants.NativeLoginRequest.ConnectSessionCode, "test-connect-session-code");
            Add(Constants.TokenRequest.UserName, "test-username");
            Add(Constants.TokenRequest.Password, "test-password");
            Add(Constants.TokenRequest.RedirectUri, "http://localhost");
            Add(Constants.NativeLoginRequest.Connect, Constants.NativeLoginRequest.ConnectTypes.NativeLogin);
        }

        public void SetScopeToInvalid()
        {
            Add(Constants.TokenRequest.Scope, "invalid");
        }

        public void RemoveUsername()
        {
            Remove(Constants.TokenRequest.UserName);
        }

        public void ChangeToLongUsername()
        {
            RemoveUsername();
            Add(Constants.TokenRequest.UserName, "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii");
        }

        public void RemovePassword()
        {
            Remove(Constants.TokenRequest.Password);
        }

        public void ChangeToLongPassword()
        {
            RemovePassword();
            Add(Constants.TokenRequest.Password, "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii");
        }
    }
}