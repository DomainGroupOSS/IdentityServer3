using IdentityServer3.Core.Extensions;

namespace IdentityServer3.Core.Validation
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="IdentityServer3.Core.Validation.ValidationResult" />
    public class NativeLoginRequestValidationResult : ValidationResult
    {
        /// <summary>
        /// Gets or sets a value indicating whether this instance is partial login.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance is partial; otherwise, <c>false</c>.
        /// </value>
        public bool IsPartial
        {
            get { return PartialReason.IsPresent(); }
        }

        public string PartialReason { get; set; }

        public string UnauthorizedReason { get; set; }

        public bool IsUnauthorized
        {
            get { return UnauthorizedReason.IsPresent(); }
        }

        public string UnauthorizedReasonDescription { get; set; }

    }
}