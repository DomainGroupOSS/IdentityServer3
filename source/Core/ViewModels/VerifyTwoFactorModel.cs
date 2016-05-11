namespace IdentityServer3.Core.ViewModels
{
    /// <summary>
    /// Verify two factor model
    /// </summary>
    public class VerifyTwoFactorModel
    {

        /// <summary>
        /// The URL to POST credentials to for local logins. Will be <c>null</c> if local login is disabled.
        /// </summary>
        /// <value>
        /// The verification code.
        /// </value>
        public string Code { get; set; }

       
        /// <summary>
        /// Indicates if "remember me" has been disabled and should not be displayed to the user.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [allow remember me]; otherwise, <c>false</c>.
        /// </value>
        public bool AllowRememberMe { get; set; }

        /// <summary>
        /// The value to populate the "remember me" field.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [remember me]; otherwise, <c>false</c>.
        /// </value>
        public bool? RememberTwoFactor { get; set; }


        /// <summary>
        /// The value to populate the "remember me" field.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [remember me]; otherwise, <c>false</c>.
        /// </value>
        public bool? RememberLogin { get; set; }

        /// <summary>
        /// User Subject
        /// </summary>
        public string Subject { get; set; }
    }
}