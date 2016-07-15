using System;
using System.ComponentModel;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Services;
using Microsoft.Owin;

namespace IdentityServer3.Core.Configuration.Hosting
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class TwoFactorCookie
    {
        private readonly IAuthenticatedTwoFactorSessionHelper _authenticatedTwoFactorTwoFactorSessionHelper;
        private readonly IOwinContext _context;
        private readonly IdentityServerOptions _identityServerOptions;


        /// <summary>
        ///     Initializes a new instance of the <see cref="TwoFactorCookie" /> class.
        /// </summary>
        /// <param name="ctx">The CTX.</param>
        /// <param name="options">The options.</param>
        /// <param name="authenticatedTwoFactorTwoFactorSessionHelper">The authenticated two factor session helper.</param>
        protected internal TwoFactorCookie(IOwinContext ctx, IdentityServerOptions options,
            IAuthenticatedTwoFactorSessionHelper authenticatedTwoFactorTwoFactorSessionHelper)
        {
            _context = ctx;
            _identityServerOptions = options;
            _authenticatedTwoFactorTwoFactorSessionHelper = authenticatedTwoFactorTwoFactorSessionHelper;
        }

        public virtual void ClearTwoFactor()
        {
            var options = CreateCookieOptions(false);
            options.Expires = DateTimeHelper.UtcNow.AddYears(-1);

            var name = GetCookieName();
            _context.Response.Cookies.Append(name, ".", options);
        }

        public virtual void IssueTwoFactorSession(bool? rememberDevice, string subjectId, DateTimeOffset? expires = null)
        {
            var twoFactorToken = _authenticatedTwoFactorTwoFactorSessionHelper.Create(subjectId);

            _context.Response.Cookies.Append(
                GetCookieName(), twoFactorToken,
                CreateCookieOptions(rememberDevice, expires));
        }

        public virtual bool IsValid(string subjectId)
        {
            var incomingToken = _context.Request.Cookies[GetCookieName()];

            return _authenticatedTwoFactorTwoFactorSessionHelper.Validate(subjectId, incomingToken);
        }


        private Microsoft.Owin.CookieOptions CreateCookieOptions(bool? rememberDevice, DateTimeOffset? expires = null)
        {
            var path = _context.Request.Environment.GetIdentityServerBasePath().CleanUrlPath();
            var secure =
                _identityServerOptions.AuthenticationOptions.CookieOptions.SecureMode == CookieSecureMode.Always ||
                _context.Request.Scheme == Uri.UriSchemeHttps;

            var options = new Microsoft.Owin.CookieOptions
            {
                HttpOnly = true,
                Secure = secure,
                Path = path
            };

            if (rememberDevice == true)
            {
                expires = expires ??
                          DateTimeHelper.UtcNow.Add(
                              this._identityServerOptions.AuthenticationOptions.CookieOptions.TwoFactorRememberThisDeviceDuration);
            }
            else
            {
                expires = expires ??
                          DateTimeHelper.UtcNow.Add(this._identityServerOptions.AuthenticationOptions.CookieOptions.TwoFactorExpireTimeSpan);
            }
            options.Expires = expires.Value.UtcDateTime;

            return options;
        }

        private string GetCookieName()
        {
            return _identityServerOptions.AuthenticationOptions.CookieOptions.GetTwoFactorCookieName();
        }
    }
}