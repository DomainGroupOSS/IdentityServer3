namespace IdentityServer3.Core.ViewModels
{
    /// <summary>
    /// Models the data needed to render the two factor challenge page.
    /// </summary>
    public class TwoFactorChallengeViewModel : ErrorViewModel
    {
        /// <summary>
        /// The URL to POST the user's two factor code. 
        /// </summary>
        /// <value>
        /// The consent URL.
        /// </value>
        public string ChallengeUrl { get; set; }

        /// <summary>
        /// The anti forgery values.
        /// </summary>
        /// <value>
        /// The anti forgery.
        /// </value>
        public AntiForgeryTokenViewModel AntiForgery { get; set; }

        /// <summary>
        /// The display name of the client.
        /// </summary>
        /// <value>
        /// The name of the client.
        /// </value>
        public string ClientName { get; set; }

        /// <summary>
        /// The URL for more information about the client.
        /// </summary>
        /// <value>
        /// The client URL.
        /// </value>
        public string ClientUrl { get; set; }

        /// <summary>
        /// The URL for the client's logo image.
        /// </summary>
        /// <value>
        /// The client logo URL.
        /// </value>
        public string ClientLogoUrl { get; set; }

        /// <summary>
        /// Value to populate the "remember this device" checkbox.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [remember this device]; otherwise, <c>false</c>.
        /// </value>
        public bool RememberThisDevice { get; set; }

        /// <summary>
        /// Gets or sets the code.
        /// </summary>
        /// <value>
        /// The code.
        /// </value>
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets the info message.
        /// </summary>
        /// <value>
        /// The info message.
        /// </value>
        public string InfoMessage { get; set; }
    }
}