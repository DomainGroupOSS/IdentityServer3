using System.Collections.Generic;
using System.ComponentModel;

namespace IdentityServer3.Core.Models
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class NativeLoginResponse
    {
        public string TokenType { get; set; }
        public string IdentityToken { get; set; }
        public string AccessToken { get; set; }
        public int AccessTokenLifetime { get; set; }
        public string RefreshToken { get; set; }
        public string Algorithm { get; set; }

        public bool IsPartial { get; set; }

        public Dictionary<string, object> Custom { get; set; }

        public NativeLoginResponse()
        {
            TokenType = Constants.ResponseTokenTypes.Bearer;
            Custom = new Dictionary<string, object>();
        }
    }
}