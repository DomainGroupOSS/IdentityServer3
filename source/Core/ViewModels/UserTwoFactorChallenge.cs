namespace IdentityServer3.Core.ViewModels
{
    /// <summary>
    /// Models the data submitted from the conset page.
    /// </summary>
    public class UserTwoFactorChallenge
    {
        /// <summary>
        /// Gets or sets the button that was clicked (either "submit" or "cancel").
        /// </summary>
        /// <value>
        /// The button.
        /// </value>
        public string Button { get; set; }

        /// <summary>
        /// Gets or sets the code.
        /// </summary>
        /// <value>
        /// The code.
        /// </value>
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the user wishes the remember 2FA on the current device.
        /// </summary>
        /// <value>
        ///   <c>true</c> if consent is to be remembered; otherwise, <c>false</c>.
        /// </value>
        public bool RememberThisDevice { get; set; }

        internal bool WantsToContinue
        {
            get
            {
                return Button == "submit";
            }
        }

        internal bool WantsToResendCode
        {
            get { return Button == "resend"; }
        }

        internal bool WantsToCancel
        {
            get { return !WantsToContinue && !WantsToResendCode; }
        }
    }
}