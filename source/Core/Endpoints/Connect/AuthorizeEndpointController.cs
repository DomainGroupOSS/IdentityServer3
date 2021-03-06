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

using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Configuration.Hosting;
using IdentityServer3.Core.Events;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.ResponseHandling;
using IdentityServer3.Core.Results;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Validation;
using IdentityServer3.Core.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Results;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace IdentityServer3.Core.Endpoints
{
    /// <summary>
    /// OAuth2/OpenID Connect authorize endpoint
    /// </summary>
    [ErrorPageFilter]
    [HostAuthentication(Constants.PrimaryAuthenticationType)]
    [SecurityHeaders]
    [NoCache]
    [PreventUnsupportedRequestMediaTypes(allowFormUrlEncoded: true)]
    internal class AuthorizeEndpointController : ApiController
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        private readonly IViewService _viewService;
        private readonly AuthorizeRequestValidator _validator;
        private readonly AuthorizeResponseGenerator _responseGenerator;
        private readonly AuthorizeInteractionResponseGenerator _interactionGenerator;
        private readonly IdentityServerOptions _options;
        private readonly ILocalizationService _localizationService;
        private readonly IEventService _events;
        private readonly AntiForgeryToken _antiForgeryToken;
        private readonly ClientListCookie _clientListCookie;
        private readonly TwoFactorCookie _twoFactorCookie;
        private readonly IUserService _userService;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizeEndpointController" /> class.
        /// </summary>
        /// <param name="viewService">The view service.</param>
        /// <param name="validator">The validator.</param>
        /// <param name="responseGenerator">The response generator.</param>
        /// <param name="interactionGenerator">The interaction generator.</param>
        /// <param name="options">The options.</param>
        /// <param name="localizationService">The localization service.</param>
        /// <param name="events">The event service.</param>
        /// <param name="userService"></param>
        /// <param name="antiForgeryToken">The anti forgery token.</param>
        /// <param name="clientListCookie">The client list cookie.</param>
        /// <param name="twoFactorCookie">The two factor cookie.</param>
        public AuthorizeEndpointController(
            IViewService viewService,
            AuthorizeRequestValidator validator,
            AuthorizeResponseGenerator responseGenerator,
            AuthorizeInteractionResponseGenerator interactionGenerator,
            IdentityServerOptions options,
            ILocalizationService localizationService,
            IEventService events,
            IUserService userService,
            AntiForgeryToken antiForgeryToken,
            ClientListCookie clientListCookie,
            TwoFactorCookie twoFactorCookie)
        {
            _viewService = viewService;
            _options = options;

            _responseGenerator = responseGenerator;
            _interactionGenerator = interactionGenerator;
            _validator = validator;
            _localizationService = localizationService;
            _events = events;
            _userService = userService;
            _antiForgeryToken = antiForgeryToken;
            _clientListCookie = clientListCookie;
            _twoFactorCookie = twoFactorCookie;
        }

        /// <summary>
        /// GET
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        [HttpGet]
        public async Task<IHttpActionResult> Get(HttpRequestMessage request)
        {
            Logger.Info("Start authorize request");

            var response = await ProcessRequestAsync(request.RequestUri.ParseQueryString());

            Logger.Info("End authorize request");
            return response;
        }

        public async Task<IHttpActionResult> ProcessRequestAsync(NameValueCollection parameters, 
            UserConsent consent = null, UserTwoFactorChallenge twoFactorChallenge = null)
        {
            // validate request
            var result = await _validator.ValidateAsync(parameters, User as ClaimsPrincipal);
            
            if (result.IsError)
            {
                return await this.AuthorizeErrorAsync(
                    result.ErrorType,
                    result.Error,
                    result.ErrorDescription,
                    result.ValidatedRequest);
            }

            var request = result.ValidatedRequest;
            var loginInteraction = await _interactionGenerator.ProcessLoginAsync(request, User as ClaimsPrincipal);

            if (loginInteraction.IsError)
            {
                return await this.AuthorizeErrorAsync(
                    loginInteraction.Error.ErrorType,
                    loginInteraction.Error.Error,
                    null,
                    request);
            }

            var context = Request.GetOwinContext();

            if (loginInteraction.IsLogin)
            {
                if (request.Client.AllowedCustomGrantTypes.Any(g => g == Constants.GrantTypes.DomainNative))
                {
                    var connectSessionCode = parameters.Get(Constants.NativeLoginRequest.ConnectSessionCode);

                    var localAuthenticationContext = new LocalAuthenticationContext
                    {
                        PasswordlessConnectType = Constants.NativeLoginRequest.ConnectTypes.NativeLogin,
                        PasswordlessConnectCode = connectSessionCode,
                        SignInMessage = loginInteraction.SignInMessage
                    };

                    await _userService.AuthenticateLocalAsync(localAuthenticationContext);

                    if (!localAuthenticationContext.AuthenticateResult.IsPartialSignIn && localAuthenticationContext.AuthenticateResult.HasSubject)
                    {
                        context.Authentication.SignIn(localAuthenticationContext.AuthenticateResult.User.Identities.ToArray());
                        User = localAuthenticationContext.AuthenticateResult.User;

                        var connectType = parameters.Get(Constants.NativeLoginRequest.Connect);

                        if (connectType == Constants.NativeLoginRequest.ConnectTypes.NativeLogin && User.Identity.IsAuthenticated)
                        {
                            await _events.RaiseNativeSuccessEventAsync(localAuthenticationContext.UserName, localAuthenticationContext.SignInMessage, localAuthenticationContext.AuthenticateResult);
                        }
                    }
                    else if (localAuthenticationContext.AuthenticateResult.IsPartialSignIn)
                    {
                        if (connectSessionCode.IsPresent())
                        {
                            return this.RedirectToLogin(loginInteraction.SignInMessage, request.Raw,
                                localAuthenticationContext.AuthenticateResult.PartialSignInRedirectPath,
                                localAuthenticationContext.AuthenticateResult);
                        }
                        throw new InvalidOperationException("User is not authenticated");
                    }
                }
                else
                {
                    return this.RedirectToLogin(loginInteraction.SignInMessage, request.Raw);
                }
            }

            // user must be authenticated at this point
            if (!User.Identity.IsAuthenticated)
            {
                throw new InvalidOperationException("User is not authenticated");
            }

            request.Subject = User as ClaimsPrincipal;

            // now that client configuration is loaded, we can do further validation
            loginInteraction = await _interactionGenerator.ProcessClientLoginAsync(request);
            if (loginInteraction.IsLogin)
            {
                return this.RedirectToLogin(loginInteraction.SignInMessage, request.Raw);
            }
            
            if (request.RequireTwoFactorChallenge)
            {
                var twoFactorInteraction = await _interactionGenerator.ProcessTwoFactorAsync(request, twoFactorChallenge);

                if (twoFactorInteraction.IsError)
                {
                    return await this.AuthorizeErrorAsync(
                        twoFactorInteraction.Error.ErrorType,
                        twoFactorInteraction.Error.Error,
                        null,
                        request);
                }

                if (twoFactorInteraction.IsTwoFactorChallenge)
                {
                    Logger.Info("Showing two factor screen");
                    return CreateTwoFactorChallengeResult(request, twoFactorChallenge, request.Raw,
                        twoFactorInteraction.TwoFactorChallengeError, twoFactorInteraction.TwoFactorChallengeInfo);
                }
                else
                {
                    _twoFactorCookie.IssueTwoFactorSession(twoFactorChallenge.RememberThisDevice, context.Authentication.User.GetSubjectId());
                }
            }

            var consentInteraction = await _interactionGenerator.ProcessConsentAsync(request, consent);

            if (consentInteraction.IsError)
            {
                return await this.AuthorizeErrorAsync(
                    consentInteraction.Error.ErrorType,
                    consentInteraction.Error.Error,
                    null,
                    request);
            }

            if (consentInteraction.IsConsent)
            {
                Logger.Info("Showing consent screen");
                return CreateConsentResult(request, consent, request.Raw, consentInteraction.ConsentError);
            }

            return await CreateAuthorizeResponseAsync(request);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public Task<IHttpActionResult> PostTwoFactorChallenge(UserTwoFactorChallenge model)
        {
            Logger.Info("Resuming from two factor challenge, restarting validation");

            return ProcessRequestAsync(Request.RequestUri.ParseQueryString(), 
                twoFactorChallenge: model ?? new UserTwoFactorChallenge());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public Task<IHttpActionResult> PostConsent(UserConsent model)
        {
            Logger.Info("Resuming from consent, restarting validation");
            return ProcessRequestAsync(Request.RequestUri.ParseQueryString(), consent: model ?? new UserConsent());
        }

        [HttpGet]
        public async Task<IHttpActionResult> LoginAsDifferentUser()
        {
            var parameters = Request.RequestUri.ParseQueryString();
            parameters[Constants.AuthorizeRequest.Prompt] = Constants.PromptModes.Login;
            return await ProcessRequestAsync(parameters);
        }

        private async Task<IHttpActionResult> CreateAuthorizeResponseAsync(ValidatedAuthorizeRequest request)
        {
            var response = await _responseGenerator.CreateResponseAsync(request);

            if (request.ResponseMode == Constants.ResponseModes.Query ||
                request.ResponseMode == Constants.ResponseModes.Fragment)
            {
                Logger.DebugFormat("Adding client {0} to client list cookie for subject {1}", request.ClientId, request.Subject.GetSubjectId());
                _clientListCookie.AddClient(request.ClientId);

                await RaiseSuccessEventAsync();
                return new AuthorizeRedirectResult(response, _options);
            }

            if (request.ResponseMode == Constants.ResponseModes.FormPost)
            {
                Logger.DebugFormat("Adding client {0} to client list cookie for subject {1}", request.ClientId, request.Subject.GetSubjectId());
                _clientListCookie.AddClient(request.ClientId);

                await RaiseSuccessEventAsync();
                return new AuthorizeFormPostResult(response, Request);
            }

            Logger.Warn("Unsupported response mode. Aborting.");
            throw new InvalidOperationException("Unsupported response mode");
        }

        private IHttpActionResult CreateTwoFactorChallengeResult(
            ValidatedAuthorizeRequest validatedRequest,
            UserTwoFactorChallenge twoFactorChallenge,
            NameValueCollection requestParameters,
            string errorMessage,
            string infoMessage)
        {
            var env = Request.GetOwinEnvironment();
            var twoFactorModel = new TwoFactorChallengeViewModel
            {
                RequestId = env.GetRequestId(),
                SiteName = _options.SiteName,
                SiteUrl = env.GetIdentityServerBaseUrl(),
                ErrorMessage = errorMessage,
                InfoMessage = infoMessage,
                CurrentUser = env.GetCurrentUserDisplayName(),
                LogoutUrl = env.GetIdentityServerLogoutUrl(),
                ClientName = validatedRequest.Client.ClientName,
                ClientUrl = validatedRequest.Client.ClientUri,
                ClientLogoUrl = validatedRequest.Client.LogoUri,
                RememberThisDevice = twoFactorChallenge != null && twoFactorChallenge.RememberThisDevice,
                ChallengeUrl = Url.Route(Constants.RouteNames.Oidc.TwoFactorChallenge, null).AddQueryString(requestParameters.ToQueryString()),
                AntiForgery = _antiForgeryToken.GetAntiForgeryToken(),                
            };

            return new TwoFactorChallengeActionResult(_viewService, twoFactorModel, validatedRequest);
        }

        private IHttpActionResult CreateConsentResult(
            ValidatedAuthorizeRequest validatedRequest,
            UserConsent consent,
            NameValueCollection requestParameters,
            string errorMessage)
        {
            string loginWithDifferentAccountUrl = null;
            if (validatedRequest.HasIdpAcrValue() == false)
            {
                loginWithDifferentAccountUrl = Url.Route(Constants.RouteNames.Oidc.SwitchUser, null)
                    .AddQueryString(requestParameters.ToQueryString());
            }
            
            var env = Request.GetOwinEnvironment();
            var consentModel = new ConsentViewModel
            {
                RequestId = env.GetRequestId(),
                SiteName = _options.SiteName,
                SiteUrl = env.GetIdentityServerBaseUrl(),
                ErrorMessage = errorMessage,
                CurrentUser = env.GetCurrentUserDisplayName(),
                LogoutUrl = env.GetIdentityServerLogoutUrl(),
                ClientName = validatedRequest.Client.ClientName,
                ClientUrl = validatedRequest.Client.ClientUri,
                ClientLogoUrl = validatedRequest.Client.LogoUri,
                IdentityScopes = validatedRequest.GetIdentityScopes(this._localizationService),
                ResourceScopes = validatedRequest.GetResourceScopes(this._localizationService),
                AllowRememberConsent = validatedRequest.Client.AllowRememberConsent,
                RememberConsent = consent == null || consent.RememberConsent,
                LoginWithDifferentAccountUrl = loginWithDifferentAccountUrl,
                ConsentUrl = Url.Route(Constants.RouteNames.Oidc.Consent, null).AddQueryString(requestParameters.ToQueryString()),
                AntiForgery = _antiForgeryToken.GetAntiForgeryToken()
            };

            return new ConsentActionResult(_viewService, consentModel, validatedRequest);
        }

        IHttpActionResult RedirectToLogin(SignInMessage message, NameValueCollection parameters, string resumeUrl = null, Models.AuthenticateResult authenticateResult = null)
        {
            message = message ?? new SignInMessage();

            var path = Url.Route(Constants.RouteNames.Oidc.Authorize, null).AddQueryString(parameters.ToQueryString());
            var host = new Uri(Request.GetOwinEnvironment().GetIdentityServerHost());
            var url = new Uri(host, path);
            message.ReturnUrl = url.AbsoluteUri;

            if (!string.IsNullOrWhiteSpace(resumeUrl))
            {
                if (resumeUrl.StartsWith("~/"))
                {
                    resumeUrl = resumeUrl.Substring(1);
                }
                if (resumeUrl.StartsWith("/"))
                {
                    resumeUrl = resumeUrl.RemoveTrailingSlash();
                }
            }

            return new LoginResult(Request.GetOwinContext().Environment, message, resumeUrl, authenticateResult);
        }

        async Task<IHttpActionResult> AuthorizeErrorAsync(ErrorTypes errorType, string error, string errorDescription, ValidatedAuthorizeRequest request)
        {
            await RaiseFailureEventAsync(error);

            // show error message to user
            if (errorType == ErrorTypes.User)
            {
                var env = Request.GetOwinEnvironment();
                var errorModel = new ErrorViewModel
                {
                    RequestId = env.GetRequestId(),
                    SiteName = _options.SiteName,
                    SiteUrl = env.GetIdentityServerBaseUrl(),
                    CurrentUser = env.GetCurrentUserDisplayName(),
                    LogoutUrl = env.GetIdentityServerLogoutUrl(),
                    ErrorMessage = LookupErrorMessage(error)
                };

                var errorResult = new ErrorActionResult(_viewService, errorModel);
                return errorResult;
            }

            // return error to client
            var response = new AuthorizeResponse
            {
                Request = request,

                IsError = true,
                Error = error,
                ErrorDescription = errorDescription,
                State = request.State,
                RedirectUri = request.RedirectUri
            };

            if (request.ResponseMode == Constants.ResponseModes.FormPost)
            {
                return new AuthorizeFormPostResult(response, Request);
            }
            else
            {
                return new AuthorizeRedirectResult(response, _options);
            }
        }

        private async Task RaiseSuccessEventAsync()
        {
            await _events.RaiseSuccessfulEndpointEventAsync(EventConstants.EndpointNames.Authorize);
        }

        private async Task RaiseFailureEventAsync(string error)
        {
            await _events.RaiseFailureEndpointEventAsync(EventConstants.EndpointNames.Authorize, error);
        }

        private string LookupErrorMessage(string error)
        {
            var msg = _localizationService.GetMessage(error);
            if (msg.IsMissing())
            {
                msg = error;
            }
            return msg;
        }
    }
}