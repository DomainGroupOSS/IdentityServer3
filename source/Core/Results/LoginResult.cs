﻿/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Models;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;

namespace IdentityServer3.Core.Results
{
    internal class LoginResult : IHttpActionResult
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        private readonly IDictionary<string, object> env;
        private readonly SignInMessage message;
        private readonly string resumeUrl;
        private readonly AuthenticateResult authResult;

        public LoginResult(IDictionary<string, object> env, SignInMessage message, string resumeUrl = null, AuthenticateResult authResult = null)
        {
            if (env == null) throw new ArgumentNullException("env");
            if (message == null) throw new ArgumentNullException("message");

            this.env = env;
            this.message = message;
            this.resumeUrl = resumeUrl;
            this.authResult = authResult;
        }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }

        private HttpResponseMessage Execute()
        {
            Logger.Info("Redirecting to login page or partial login");

            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            var signinId = string.Empty;
            var url = this.env.CreateSignInRequest(this.message, out signinId, resumeUrl);

            if (!string.IsNullOrWhiteSpace(resumeUrl) && !string.IsNullOrWhiteSpace(signinId))
            {
                var ctx = new OwinContext(env);
                ctx.IssuePartialLoginCookie(authResult, resumeUrl, signinId);
            }

            response.Headers.Location = new Uri(url);
            return response;
        }
    }
}