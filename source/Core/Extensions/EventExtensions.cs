using System;
using IdentityServer3.Core.Logging;
using Microsoft.Owin;
using UAParser;
using IdentityServer3.Core.Extensions;

namespace IdentityServer3.Core.Events
{
    public static class EventExtensions
    {
        private static readonly UAParser.Parser parser = Parser.GetDefault();
        private static readonly ILog Logger = LogProvider.GetLogger("Events");

        public static void AddUserAgentDetails<T>(this Event<T> evt, OwinContext context)
        {
            if (!context.Request.Headers.ContainsKey("User-Agent"))
            {
                return;
            }

            var userAgent = context.Request.Headers.Get("User-Agent");

            if (context.Request.Headers.ContainsKey("X-Forwarded-User-Agent"))
            {
                userAgent = context.Request.Headers.Get("X-Forwarded-User-Agent");
            }

            if (userAgent.IsMissing())
            {
                Logger.DebugFormat("Can't set user agent details on event {0}, missing User-Agent request header", evt.GetType().FullName);
                return;
            }

            try
            {
                var client = parser.Parse(userAgent);

                var browserVersion = client.UserAgent.Major + (client.UserAgent.Minor.IsPresent() ? "." + client.UserAgent.Minor : string.Empty);
                evt.Context.Browser = string.Format("{0} {1}", client.UserAgent.Family, browserVersion);

                var device = client.Device.Family + (client.Device.Brand.IsPresent() ? " " + client.Device.Brand : string.Empty);
                evt.Context.Device = device;

                var osVersion = client.OS.Major + (client.OS.Minor.IsPresent() ? "." + client.OS.Minor : string.Empty);
                evt.Context.OperatingSystem = string.Format("{0} {1}", client.OS.Family, osVersion);

            }
            catch (Exception ex)
            {
                Logger.Error(ex.Message);
            }
        }
    }
}