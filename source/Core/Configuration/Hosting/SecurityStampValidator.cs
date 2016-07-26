using System;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Services;
using Microsoft.Owin.Security.Cookies;

namespace IdentityServer3.Core.Configuration.Hosting
{
    /// <summary>
    ///     Static helper class used to configure a CookieAuthenticationNotifications to validate a cookie against a user's
    ///     security stamp.
    /// </summary>
    public class SecurityStampValidator
    {
        internal static async Task ValidatePrincipalAsync(CookieValidateIdentityContext cookieValidateIdentityContext,
            CookieOptions cookieOptions)
        {
            var currentUtc = DateTimeOffset.UtcNow;
            if (cookieValidateIdentityContext.Options != null && cookieValidateIdentityContext.Options.SystemClock != null)
            {
                currentUtc = cookieValidateIdentityContext.Options.SystemClock.UtcNow;
            }
            var issuedUtc = cookieValidateIdentityContext.Properties.IssuedUtc;

            // Only validate if enough time has elapsed
            var validate = (issuedUtc == null);
            if (issuedUtc != null)
            {
                var timeElapsed = currentUtc.Subtract(issuedUtc.Value);
                validate = timeElapsed > cookieOptions.SecurityStampValidationInterval;
            }
            if (!validate)
            {
                await Task.FromResult(0);
                return;
            }

            var validator = cookieValidateIdentityContext.OwinContext.Environment.ResolveDependency<IAuthenticationSessionValidator>();
            var isValid = await validator.IsAuthenticationSessionValidAsync(new ClaimsPrincipal(cookieValidateIdentityContext.Identity));

            if (!isValid)
            {
                cookieValidateIdentityContext.RejectIdentity();
                cookieValidateIdentityContext.OwinContext.Authentication.SignOut(Constants.PrimaryAuthenticationType,
                    Constants.ExternalAuthenticationType);

                var twoFactorCookie = cookieValidateIdentityContext.OwinContext.Environment.ResolveDependency<TwoFactorCookie>();

                if (twoFactorCookie != null)
                {
                    twoFactorCookie.ClearTwoFactor();
                }
            }
        }
    }
}