
namespace IdentityServer3.Core.Models
{
    /// <summary>
    /// Signed in user data to be written out as cookies.
    /// </summary>
    public class LastUserNameCookieMessage : Message
    {
        /// <summary>
        /// Gets or sets the UserName
        /// </summary>
        /// <value>
        /// The UserName
        /// </value>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the Profile picture path
        /// </summary>
        /// <value>
        /// The profile picture path
        /// </value>
        public string ProfilePicturePath { get; set; }
    }
}