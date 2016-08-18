using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using IdentityModel;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using Microsoft.Owin;

#pragma warning disable 1591

namespace IdentityServer3.Core.Configuration.Hosting
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class ProfileImageCookie
    {
        const string ProfileImageCookieName = "idsvr.profileimage";
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();

        readonly IOwinContext ctx;
        readonly IdentityServerOptions options;

        internal ProfileImageCookie(IOwinContext ctx, IdentityServerOptions options)
        {
            if (ctx == null)
            {
                throw new ArgumentNullException("ctx");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            this.ctx = ctx;
            this.options = options;
        }

        internal string GetValue()
        {
            try
            {
                var cookieName = options.AuthenticationOptions.CookieOptions.Prefix + ProfileImageCookieName;
                var value = ctx.Request.Cookies[cookieName];

                var bytes = Base64Url.Decode(value);
                try
                {
                    bytes = options.DataProtector.Unprotect(bytes, cookieName);
                }
                catch (CryptographicException)
                {
                    SetValue(null);
                    return null;
                }
                value = Encoding.UTF8.GetString(bytes);

                return value;
            }
            catch
            {
                SetValue(null);
            }
            return null;
        }

        internal void SetValue(string imagePath)
        {
            var cookieName = options.AuthenticationOptions.CookieOptions.Prefix + ProfileImageCookieName;
            var secure =
                options.AuthenticationOptions.CookieOptions.SecureMode == CookieSecureMode.Always ||
                ctx.Request.Scheme == Uri.UriSchemeHttps;
            var path = ctx.Request.Environment.GetIdentityServerBasePath().CleanUrlPath();

            var cookieOptions = new Microsoft.Owin.CookieOptions
            {
                HttpOnly = true,
                Secure = secure,
                Path = path
            };

            if (!String.IsNullOrWhiteSpace(imagePath))
            {
                var bytes = Encoding.UTF8.GetBytes(imagePath);
                bytes = options.DataProtector.Protect(bytes, cookieName);
                imagePath = Base64Url.Encode(bytes);
                cookieOptions.Expires = DateTimeHelper.UtcNow.AddYears(1);
            }
            else
            {
                imagePath = ".";
                cookieOptions.Expires = DateTimeHelper.UtcNow.AddYears(-1);
            }

            ctx.Response.Cookies.Append(cookieName, imagePath, cookieOptions);
        }
    }
}