using System.Collections.Specialized;
using IdentityServer3.Core;

namespace IdentityServer3.Tests.TokenClients.Setup
{
    public class AuthorizationCodeTestParameters : NameValueCollection
    {
        public AuthorizationCodeTestParameters()
        {
            Add(Constants.TokenRequest.GrantType, Constants.GrantTypes.AuthorizationCode);
            Add(Constants.TokenRequest.Code, "test-connect-code");
            Add(Constants.NativeLoginRequest.Connect, Constants.NativeLoginRequest.ConnectTypes.NativeLogin);
            Add(Constants.TokenRequest.RedirectUri, "https://test.domain.com.au");
        }

        public void RemoveCode()
        {
            Remove(Constants.TokenRequest.Code);
        }

        public void ChangeToLongCode()
        {
            RemoveCode();
            Add(Constants.TokenRequest.Code,
                "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii");
        }

        public void SetDefaultCodeVerifier()
        {
            Add(Constants.TokenRequest.CodeVerifier,
                "bacon-ipsum-dolor-amet-cupim-pork-belly-flank-kielbasa-fatback-t-bone-ham-hock-shankle-pancetta");
        }

        public void SetToLongCodeVerifier()
        {
            Add(Constants.TokenRequest.CodeVerifier,
                "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii");
        }

        public void RemoveRedirectUri()
        {
            Remove(Constants.TokenRequest.RedirectUri);
        }

        public void SetToWrongRedirectUri()
        {
            RemoveRedirectUri();
            Add(Constants.TokenRequest.RedirectUri, "https://BEEP.BOOP");
        }

        public void AddPoPTokenType()
        {
            Add("token_type", Constants.ResponseTokenTypes.PoP);
        }
    }
}