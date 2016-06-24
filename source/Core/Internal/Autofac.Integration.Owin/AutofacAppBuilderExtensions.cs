// This software is part of the Autofac IoC container
// Copyright © 2014 Autofac Contributors
// http://autofac.org
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security;
using Autofac;
using Autofac.Core;
using Autofac.Core.Lifetime;
using Autofac.Integration.Owin;
using IdentityServer3.Core.Logging;
using Microsoft.Owin;

namespace Owin
{
    /// <summary>
    ///     Extension methods for configuring Autofac within the OWIN pipeline.
    /// </summary>
    [SecuritySafeCritical]
    [EditorBrowsable(EditorBrowsableState.Never)]
    internal static class OwinExtensions
    {
        // idsvr : unnecessary because we remove these guards so that multiple copies of middleware can be registered
        //const string MiddlewareRegisteredKey = "idsvr:AutofacMiddelwareRegistered";
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();

        /// <summary>
        ///     Adds a component to the OWIN pipeline for using Autofac dependency injection with middleware.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <param name="container">The Autofac application lifetime scope/container.</param>
        /// <returns>The application builder.</returns>
        [SecuritySafeCritical]
        public static IAppBuilder UseAutofacMiddleware(this IAppBuilder app, ILifetimeScope container)
        {
            if (app == null) throw new ArgumentNullException("app");

            // idsvr : remove these guards so that multiple copies of middleware can be registered
            //if (app.Properties.ContainsKey(MiddlewareRegisteredKey)) return app;

            app.Use(async (context, next) =>
            {
                using (var lifetimeScope = container.BeginLifetimeScope(MatchingScopeLifetimeTags.RequestLifetimeScopeTag,
                    b => b.RegisterInstance(context).As<IOwinContext>()))
                {
                    context.Set(Constants.OwinLifetimeScopeKey, lifetimeScope);
                    await next();
                }
            });

            // idsvr : remove these guards so that multiple copies of middleware can be registered
            //app.Properties.Add(MiddlewareRegisteredKey, true);

            return app;
        }

        [SecuritySafeCritical]
        internal static void UseMiddlewareFromContainer(this IAppBuilder app, IComponentContext container,
            IDictionary<string, Type> controllerRoutes)
        {
            var controllerTypes = controllerRoutes == null ? Enumerable.Empty<Type>() : (controllerRoutes.Select(r => r.Value));

            var controllers = container.ComponentRegistry.Registrations.SelectMany(r => r.Services)
                .OfType<TypedService>()
                .Where(s => s.ServiceType.IsAssignableTo<OwinMiddleware>()
                            && typeof(IOwinController).IsAssignableFrom(s.ServiceType) && !s.ServiceType.IsAbstract)
                .Select(service => typeof(AutofacMiddleware<>).MakeGenericType(service.ServiceType))
                .Where(serviceType => !container.IsRegistered(serviceType)).Except(controllerTypes);

            var middlewareComponents = container.ComponentRegistry.Registrations.SelectMany(r => r.Services)
                .OfType<TypedService>()
                .Where(s => s.ServiceType.IsAssignableTo<OwinMiddleware>() && !s.ServiceType.IsAbstract)
                .Select(service => typeof(AutofacMiddleware<>).MakeGenericType(service.ServiceType))
                .Where(serviceType => !container.IsRegistered(serviceType)).Except(controllerTypes)
                .Except(controllers);

            var typedMiddleware = middlewareComponents.ToArray();
            var typedControllers = controllers.ToArray();


            if (!typedMiddleware.Any())
            {
                Logger.Info("There were no OwinMiddleware components registered");
            }
            else
            {
                foreach (var middleware in typedMiddleware)
                {
                    Logger.InfoFormat("Using OwinMiddlware - {0}", middleware.FullName);
                    app.Use(middleware);
                }
            }

            if (!typedControllers.Any())
            {
                Logger.Info("There were no OwinControllers registered with the container");
            }
            else
            {
                foreach (var route in controllerRoutes)
                {
                    var route1 = route;

                    app.MapWhen(context => context.Request.Uri.GetLeftPart(UriPartial.Path).EndsWith(route1.Key), builder =>
                    {
                        Logger.InfoFormat("Using OwinController - {0}", route1.Value.FullName);

                        var controller = typedControllers.FirstOrDefault(c => c.GetGenericArguments().First() == route1.Value);
                        if (controller != null)
                        {
                            builder.Use(controller);
                        }
                    });
                }
            }
        }
    }
}