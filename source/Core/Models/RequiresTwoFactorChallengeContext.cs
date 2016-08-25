using System;
using System.Security.Claims;

namespace IdentityServer3.Core.Models
{
    public class RequiresTwoFactorChallengeContext
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IsActiveContext"/> class.
        /// </summary>
        public RequiresTwoFactorChallengeContext(ClaimsPrincipal subject, Client client)
        {
            if (subject == null) throw new ArgumentNullException("subject");
            if (client == null) throw new ArgumentNullException("client");

            Subject = subject;
            Client = client;

            ShouldChallenge = false;
        }

        /// <summary>
        /// Gets or sets the subject.
        /// </summary>
        /// <value>
        /// The subject.
        /// </value>
        public ClaimsPrincipal Subject { get; set; }

        /// <summary>
        /// Gets or sets the client.
        /// </summary>
        /// <value>
        /// The client.
        /// </value>
        public Client Client { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the subject is active and can recieve tokens.
        /// </summary>
        /// <value>
        ///   <c>true</c> if the subject is active; otherwise, <c>false</c>.
        /// </value>
        public bool ShouldChallenge { get; set; }

        public string ChallengeRedirectUri { get; set; }
    }
}