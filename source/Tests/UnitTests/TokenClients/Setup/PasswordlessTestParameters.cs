using System.Collections.Specialized;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Tests.TokenClients.Setup
{
    public class PasswordlessTestParameters : NameValueCollection
    {
        public PasswordlessTestParameters()
        {
            Add(Constants.TokenRequest.GrantType, Constants.GrantTypes.Passwordless);
            Add(Constants.TokenRequest.Scope, StandardScopes.Profile.Name);
            Add(Constants.NativeLoginRequest.ConnectChallenge, "test-connect-code");
            Add(Constants.NativeLoginRequest.ConnectSessionCode,"test-connect-session-code");
            Add(Constants.TokenRequest.UserName, "test-username");
            Add(Constants.TokenRequest.RedirectUri, "http://localhost");
            Add(Constants.NativeLoginRequest.Connect, Constants.NativeLoginRequest.ConnectTypes.NativeLogin);
        }

        public void RemoveConnectType()
        {
            Remove(Constants.NativeLoginRequest.Connect);
        }

        public void ChangeToEmailConnectType()
        {
            RemoveConnectType();
            Add(Constants.NativeLoginRequest.Connect, Constants.NativeLoginRequest.ConnectTypes.Email);
        }

        public void ChangeToMobilePhoneConnectType()
        {
            RemoveConnectType();
            Add(Constants.NativeLoginRequest.Connect, Constants.NativeLoginRequest.ConnectTypes.MobilePhone);
        }

        public void ChangeToOtpConnectType()
        {
            RemoveConnectType();
            Add(Constants.NativeLoginRequest.Connect, Constants.NativeLoginRequest.ConnectTypes.Otp);
        }

        public void ChangeToInvalidConnectType()
        {
            RemoveConnectType();
            Add(Constants.NativeLoginRequest.Connect, "invalid");
        }

        public void RemoveSessionCode()
        {
            Remove(Constants.NativeLoginRequest.ConnectSessionCode);
        }

        public void ChangeToLongSessionCode()
        {
            RemoveSessionCode();
            Add(Constants.NativeLoginRequest.ConnectSessionCode, "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii");
        }

        public void RemoveConnectCode()
        {
            Remove(Constants.NativeLoginRequest.ConnectChallenge);
        }

        public void AddAcrValues()
        {
            
        }

        public void RemoveGrantType()
        {
            Remove(Constants.TokenRequest.GrantType);
        }

        public void ChangeToLongGrantType()
        {
            Remove(Constants.TokenRequest.GrantType);
            Add(Constants.TokenRequest.GrantType, "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii");
        }

        public void ChangeToInvalidScope()
        {
            RemoveScope();
            Add(Constants.TokenRequest.Scope, "invalid-scope");
        }

        public void RemoveUsername()
        {
            Remove(Constants.TokenRequest.UserName);
        }

        public void RemoveRedirectUri()
        {
            Remove(Constants.TokenRequest.RedirectUri);
        }

        public void RemoveScope()
        {
            Remove(Constants.TokenRequest.Scope);
        }
    }
}