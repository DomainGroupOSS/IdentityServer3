using System.Collections.Generic;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Core.Validation
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="IdentityServer3.Core.Validation.ValidatedRequest" />
    public class ValidatedNativeLoginRequest : ValidatedRequest
    {
        /// <summary>
        /// Initializes the validated request with default values.
        /// </summary>
        public ValidatedNativeLoginRequest()
        {
            RequestedTokenType = RequestedTokenTypes.Bearer;
            IsPartiallyAuthenticated = false;
        }

        /// <summary>
        /// Gets or sets the requested token type.
        /// </summary>
        /// <value>
        /// The requested token type.
        /// </value>
        public RequestedTokenTypes RequestedTokenType { get; set; }

        /// <summary>
        /// Gets or sets the client.
        /// </summary>
        /// <value>
        /// The client.
        /// </value>
        public Client Client { get; set; }

        /// <summary>
        /// Gets or sets the type of the grant.
        /// </summary>
        /// <value>
        /// The type of the grant.
        /// </value>
        public string GrantType { get; set; }

        /// <summary>
        /// Gets or sets the scopes.
        /// </summary>
        /// <value>
        /// The scopes.
        /// </value>
        public IEnumerable<string> Scopes { get; set; }

        /// <summary>
        /// Gets or sets the username used in the request.
        /// </summary>
        /// <value>
        /// The name of the user.
        /// </value>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the sign in message.
        /// </summary>
        /// <value>
        /// The sign in message.
        /// </value>
        public SignInMessage SignInMessage { get; set; }

        /// <summary>
        /// Gets or sets the refresh token.
        /// </summary>
        /// <value>
        /// The refresh token.
        /// </value>
        public RefreshToken RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the refresh token handle.
        /// </summary>
        /// <value>
        /// The refresh token handle.
        /// </value>
        public string RefreshTokenHandle { get; set; }

        /// <summary>
        /// Gets or sets the authorization code.
        /// </summary>
        /// <value>
        /// The authorization code.
        /// </value>
        public AuthorizationCode AuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets the authorization code handle.
        /// </summary>
        /// <value>
        /// The authorization code handle.
        /// </value>
        public string AuthorizationCodeHandle { get; set; }

        /// <summary>
        /// Gets or sets the code verifier.
        /// </summary>
        /// <value>
        /// The code verifier.
        /// </value>
        public string CodeVerifier { get; set; }

        /// <summary>
        /// Gets or sets the algorithm used for the proof key
        /// </summary>
        /// <value>
        /// The algorithm name.
        /// </value>
        public string ProofKeyAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the proof key
        /// </summary>
        /// <value>
        /// The proof key.
        /// </value>
        public string ProofKey { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this instance is partially authenticated.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance is partially authenticated; otherwise, <c>false</c>.
        /// </value>
        public bool IsPartiallyAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the next partial action.
        /// </summary>
        /// <value>
        /// The next partial action.
        /// </value>
        public string PartialReason { get; set; }

        /// <summary>
        /// Gets or sets the connect code e.g. sms or totp
        /// </summary>
        /// <value>
        /// The connect code.
        /// </value>
        public string PasswordlessConnectCode { get; set; }

        /// <summary>
        /// Gets or sets the passwordless connect type e.g. sms, totp, push
        /// </summary>
        /// <value>
        /// The passwordless connect.
        /// </value>
        public string PasswordlessConnect { get; set;  }

        /// <summary>
        /// Gets or sets the authentication code.
        /// </summary>
        /// <value>
        /// The authentication code.
        /// </value>
        public string PasswordlessOtp { get; set; }
    }
}