using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;

namespace IdentityServer3.Core.Validation
{
    internal class NativeLoginRequestValidator
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        private readonly IdentityServerOptions _options;
        private readonly IAuthorizationCodeStore _authorizationCodes;
        private readonly IUserService _users;
        private readonly CustomGrantValidator _customGrantValidator;
        private readonly IRefreshTokenStore _refreshTokens;
        private readonly ScopeValidator _scopeValidator;
        private readonly IEventService _events;
        private readonly ITwoFactorService _twoFactorService;
        private readonly IRedirectUriValidator _uriValidator;

        private static readonly IEnumerable<string> AllowedGrantTypes = new[]
        {
            Constants.GrantTypes.AuthorizationCode,
            Constants.GrantTypes.RefreshToken,
            Constants.GrantTypes.Password,
            Constants.GrantTypes.Passwordless
        };

        public static readonly IEnumerable<string> AllowedConnectTypes = new[]
        {
            Constants.NativeLoginRequest.ConnectTypes.Sms,
            Constants.NativeLoginRequest.ConnectTypes.Totp,
            Constants.NativeLoginRequest.ConnectTypes.Otp,
            Constants.NativeLoginRequest.ConnectTypes.NativeLogin,
            Constants.NativeLoginRequest.ConnectTypes.Email,
            Constants.NativeLoginRequest.ConnectTypes.MobilePhone
        };

        private ValidatedNativeLoginRequest _validatedRequest;

        public ValidatedNativeLoginRequest ValidatedRequest
        {
            get
            {
                return _validatedRequest;
            }
        }

        public NativeLoginRequestValidator(IdentityServerOptions options, 
            IAuthorizationCodeStore authorizationCodes, 
            IRefreshTokenStore refreshTokens, IUserService users, 
            CustomGrantValidator customGrantValidator, 
            ScopeValidator scopeValidator, 
            IEventService events, 
            ITwoFactorService twoFactorService,
            IRedirectUriValidator uriValidator)
        {
            _options = options;
            _authorizationCodes = authorizationCodes;
            _refreshTokens = refreshTokens;
            _users = users;
            _customGrantValidator = customGrantValidator;
            _scopeValidator = scopeValidator;
            _events = events;
            _twoFactorService = twoFactorService;
            _uriValidator = uriValidator;
        }

        public async Task<NativeLoginRequestValidationResult> ValidateRequestAsync(NameValueCollection parameters, Client client)
        {
            Logger.Info("Start token request validation");

            _validatedRequest = new ValidatedNativeLoginRequest();

            if (client == null)
            {
                throw new ArgumentNullException("client");
            }

            if (parameters == null)
            {
                throw new ArgumentNullException("parameters");
            }

            _validatedRequest.Raw = parameters;
            _validatedRequest.Client = client;
            _validatedRequest.Options = _options;

            /////////////////////////////////////////////
            // check grant type
            /////////////////////////////////////////////
            var grantType = parameters.Get(Constants.TokenRequest.GrantType);
            if (grantType.IsMissing())
            {
                LogError("Grant type is missing.");
                return Invalid(Constants.NativeLoginErrors.UnsupportedGrantType);
            }

            if (grantType.Length > _options.InputLengthRestrictions.GrantType)
            {
                LogError("Grant type is too long.");
                return Invalid(Constants.NativeLoginErrors.UnsupportedGrantType);
            }

            if (_validatedRequest.Client.AllowedCustomGrantTypes.All(g => !AllowedGrantTypes.Contains(g)))
            {
                _validatedRequest.GrantType = grantType;
            }

            switch (grantType)
            {
                case Constants.GrantTypes.AuthorizationCode:
                    return await RunValidationAsync(ValidateAuthorizationCodeRequestAsync, parameters);
                case Constants.GrantTypes.Password:
                    return await RunValidationAsync(ValidateResourceOwnerCredentialRequestAsync, parameters);
                case Constants.GrantTypes.RefreshToken:
                    return await RunValidationAsync(ValidateRefreshTokenRequestAsync, parameters);
                case Constants.GrantTypes.Passwordless:
                    return await RunValidationAsync(ValidatePasswordlessRequestAsync, parameters);
            }

            LogError("Unsupported grant_type: " + grantType);
            return Invalid(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        async Task<NativeLoginRequestValidationResult> RunValidationAsync(Func<NameValueCollection, Task<NativeLoginRequestValidationResult>> validationFunc, NameValueCollection parameters)
        {
            // run standard validation
            var result = await validationFunc(parameters);
            if (result.IsError)
            {
                return result;
            }          

            LogSuccess();
            return result;
        }

        private async Task<NativeLoginRequestValidationResult> ValidateAuthorizationCodeRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start validation of authorization code token request");

            /////////////////////////////////////////////
            // check if client is authorized for grant type
            /////////////////////////////////////////////

            if (!_validatedRequest.Client.AllowedCustomGrantTypes.Contains(Constants.GrantTypes.DomainNative))
            {
                LogError("Client not authorized for code flow");
                return Invalid(Constants.NativeLoginErrors.UnauthorizedClient);
            }

            /////////////////////////////////////////////
            // validate authorization code
            /////////////////////////////////////////////
            var code = parameters.Get(Constants.TokenRequest.Code);
            if (code.IsMissing())
            {
                var error = "Authorization code is missing.";
                LogError(error);
                await RaiseFailedAuthorizationCodeRedeemedEventAsync(null, error);

                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            if (code.Length > _options.InputLengthRestrictions.AuthorizationCode)
            {
                var error = "Authorization code is too long.";
                LogError(error);
                await RaiseFailedAuthorizationCodeRedeemedEventAsync(null, error);

                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            _validatedRequest.AuthorizationCodeHandle = code;

            var authZcode = await _authorizationCodes.GetAsync(code);
            if (authZcode == null)
            {
                LogError("Invalid authorization code: " + code);
                await RaiseFailedAuthorizationCodeRedeemedEventAsync(code, "Invalid handle");

                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            await _authorizationCodes.RemoveAsync(code);

            /////////////////////////////////////////////
            // populate session id
            /////////////////////////////////////////////
            if (authZcode.SessionId.IsPresent())
            {
                _validatedRequest.SessionId = authZcode.SessionId;
            }

            /////////////////////////////////////////////
            // validate client binding
            /////////////////////////////////////////////
            if (authZcode.Client.ClientId != _validatedRequest.Client.ClientId)
            {
                LogError(string.Format("Client {0} is trying to use a code from client {1}", _validatedRequest.Client.ClientId, authZcode.Client.ClientId));
                await RaiseFailedAuthorizationCodeRedeemedEventAsync(code, "Invalid client binding");

                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            /////////////////////////////////////////////
            // validate PKCE parameters
            /////////////////////////////////////////////
            var codeVerifier = parameters.Get(Constants.TokenRequest.CodeVerifier);
            if (authZcode.Client.Flow == Flows.AuthorizationCodeWithProofKey ||
                authZcode.Client.Flow == Flows.HybridWithProofKey)
            {
                var proofKeyResult = ValidateAuthorizationCodeWithProofKeyParameters(codeVerifier, authZcode);
                if (proofKeyResult.IsError)
                {
                    return proofKeyResult;
                }

                _validatedRequest.CodeVerifier = codeVerifier;
            }
            else
            {
                if (codeVerifier.IsPresent())
                {
                    LogError("Unexpected code_verifier with Flow " + authZcode.Client.Flow.ToString());
                    return Invalid(Constants.NativeLoginErrors.InvalidGrant);
                }
            }

            /////////////////////////////////////////////
            // validate code expiration
            /////////////////////////////////////////////
            if (authZcode.CreationTime.HasExceeded(_validatedRequest.Client.AuthorizationCodeLifetime))
            {
                var error = "Authorization code is expired";
                LogError(error);
                await RaiseFailedAuthorizationCodeRedeemedEventAsync(code, error);

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            _validatedRequest.AuthorizationCode = authZcode;

            /////////////////////////////////////////////
            // validate redirect_uri
            /////////////////////////////////////////////
            var redirectUri = parameters.Get(Constants.TokenRequest.RedirectUri);
            if (redirectUri.IsMissing())
            {
                var error = "Redirect URI is missing.";
                LogError(error);
                await RaiseFailedAuthorizationCodeRedeemedEventAsync(code, error);

                return Invalid(Constants.TokenErrors.UnauthorizedClient);
            }

            if (_validatedRequest.Client.AllowedCustomGrantTypes.All(g => !AllowedGrantTypes.Contains(g)))
            {
                if (redirectUri.Equals(_validatedRequest.AuthorizationCode.RedirectUri, StringComparison.Ordinal) == false)
                {
                    var error = "Invalid redirect_uri: " + redirectUri;
                    LogError(error);
                    await RaiseFailedAuthorizationCodeRedeemedEventAsync(code, error);

                    return Invalid("The redirect URI in the request, " + _validatedRequest.AuthorizationCode.RedirectUri + ", does not match the ones authorized for the OAuth client.");
                }
            }

            /////////////////////////////////////////////
            // validate scopes are present
            /////////////////////////////////////////////
            if (_validatedRequest.AuthorizationCode.RequestedScopes == null ||
                !_validatedRequest.AuthorizationCode.RequestedScopes.Any())
            {
                var error = "Authorization code has no associated scopes.";
                LogError(error);
                await RaiseFailedAuthorizationCodeRedeemedEventAsync(code, error);

                return Invalid(Constants.TokenErrors.InvalidRequest);
            }

            /////////////////////////////////////////////
            // make sure user is enabled
            /////////////////////////////////////////////
            var isActiveCtx = new IsActiveContext(_validatedRequest.AuthorizationCode.Subject, _validatedRequest.Client);
            await _users.IsActiveAsync(isActiveCtx);

            if (isActiveCtx.IsActive == false)
            {
                var error = "User has been disabled: " + _validatedRequest.AuthorizationCode.Subject;
                LogError(error);
                await RaiseFailedAuthorizationCodeRedeemedEventAsync(code, error);

                return Invalid(Constants.TokenErrors.InvalidRequest);
            }

            /////////////////////////////////////////////
            // validate token type and PoP parameters if pop token is requested
            /////////////////////////////////////////////
            var tokenType = parameters.Get("token_type");
            if (tokenType != null && tokenType == Constants.ResponseTokenTypes.PoP)
            {
                var result = ValidatePopParameters(parameters);
                if (result.IsError)
                {
                    var error = "PoP parameter validation failed: " + result.ErrorDescription;
                    LogError(error);
                    await RaiseFailedAuthorizationCodeRedeemedEventAsync(code, error);

                    return Invalid(result.Error, result.ErrorDescription);
                }
                else
                {
                    _validatedRequest.RequestedTokenType = RequestedTokenTypes.PoP;
                }
            }

            Logger.Info("Validation of authorization code token request success");
            await RaiseSuccessfulAuthorizationCodeRedeemedEventAsync();

            return Valid();
        }

        private async Task<NativeLoginRequestValidationResult> ValidateResourceOwnerCredentialRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start password token request validation");

            // if we've disabled local authentication, then fail
            if (_options.AuthenticationOptions.EnableLocalLogin == false ||
                _validatedRequest.Client.EnableLocalLogin == false)
            {
                LogError("EnableLocalLogin is disabled, failing with UnsupportedGrantType");
                return Invalid(Constants.NativeLoginErrors.UnsupportedGrantType);
            }

            /////////////////////////////////////////////
            // check if client is authorized for grant type
            /////////////////////////////////////////////
            if (!_validatedRequest.Client.AllowedCustomGrantTypes.Contains(Constants.GrantTypes.DomainNative))
            {
                LogError("Client not authorized for resource owner flow");
                return Invalid(Constants.NativeLoginErrors.UnauthorizedClient);
            }

            /////////////////////////////////////////////
            // check if client is allowed to request scopes
            /////////////////////////////////////////////
            if (!(await ValidateRequestedScopesAsync(parameters)))
            {
                LogError("Invalid scopes.");
                return Invalid(Constants.NativeLoginErrors.InvalidScope);
            }

            /////////////////////////////////////////////
            // check resource owner credentials
            /////////////////////////////////////////////
            var userName = parameters.Get(Constants.TokenRequest.UserName);
            var password = parameters.Get(Constants.TokenRequest.Password);

            if (userName.IsMissing() || password.IsMissing())
            {
                LogError("Username or password missing.");
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            if (userName.Length > _options.InputLengthRestrictions.UserName ||
                password.Length > _options.InputLengthRestrictions.Password)
            {
                LogError("Username or password too long.");
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            _validatedRequest.UserName = userName;

            /////////////////////////////////////////////
            // check optional parameters and populate SignInMessage
            /////////////////////////////////////////////
            var signInMessage = new SignInMessage();

            // pass through client_id
            signInMessage.ClientId = _validatedRequest.Client.ClientId;

            // process acr values
            var acr = parameters.Get(Constants.AuthorizeRequest.AcrValues);
            if (acr.IsPresent())
            {
                if (acr.Length > _options.InputLengthRestrictions.AcrValues)
                {
                    LogError("Acr values too long.");
                    return Invalid(Constants.NativeLoginErrors.InvalidRequest);
                }

                var acrValues = acr.FromSpaceSeparatedString().Distinct().ToList();

                // look for well-known acr value -- idp
                var idp = acrValues.FirstOrDefault(x => x.StartsWith(Constants.KnownAcrValues.HomeRealm));
                if (idp.IsPresent())
                {
                    signInMessage.IdP = idp.Substring(Constants.KnownAcrValues.HomeRealm.Length);
                    acrValues.Remove(idp);
                }

                // look for well-known acr value -- tenant
                var tenant = acrValues.FirstOrDefault(x => x.StartsWith(Constants.KnownAcrValues.Tenant));
                if (tenant.IsPresent())
                {
                    signInMessage.Tenant = tenant.Substring(Constants.KnownAcrValues.Tenant.Length);
                    acrValues.Remove(tenant);
                }

                // pass through any remaining acr values
                if (acrValues.Any())
                {
                    signInMessage.AcrValues = acrValues;
                }
            }

            _validatedRequest.SignInMessage = signInMessage;

            /////////////////////////////////////////////
            // authenticate user
            /////////////////////////////////////////////
            var authenticationContext = new LocalAuthenticationContext
            {
                UserName = userName,
                Password = password,
                SignInMessage = signInMessage
            };

            await _users.AuthenticateLocalAsync(authenticationContext);
            var authnResult = authenticationContext.AuthenticateResult;         

            if (authnResult == null || authnResult.IsError)
            {
                var error = Resources.Messages.InvalidUsernameOrPassword;
                if (authnResult != null && authnResult.IsError)
                {
                    LogError("User authentication failed: " + authnResult.ErrorMessage);
                    await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, signInMessage, authnResult.ErrorMessage);
                }
               
                if (authnResult != null)
                {
                    return Invalid(error, authnResult.ErrorMessage);
                }

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            _validatedRequest.IsPartiallyAuthenticated = authnResult.IsPartialSignIn;
            _validatedRequest.UserName = userName;
            _validatedRequest.Subject = authnResult.User;
                                   

            if (authnResult.IsPartialSignIn)
            {
                _validatedRequest.PartialReason = authnResult.PartialSignInReason;

                Logger.InfoFormat("Native login partial signin reason: {0}", authnResult.PartialSignInReason);


                if (authnResult.PartialSignInReason == Constants.NativeLoginPartialReasons.TwoFactorChallengeRequired)
                {
                    Logger.InfoFormat("Request two-factor code for subject: {0}", authnResult.User.GetSubjectId());

                    await _twoFactorService.RequestCodeAsync(_validatedRequest.Client, authnResult.User);
                }

                return Partial(authnResult.PartialSignInReason);
            }

            await RaiseSuccessfulResourceOwnerAuthenticationEventAsync(userName, authnResult.User.GetSubjectId(), signInMessage);
            Logger.Info("Password native log request validation success.");

            return Valid();
        }

        private async Task<NativeLoginRequestValidationResult> ValidatePasswordlessRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start passwordless token request validation");

            // if we've disabled local authentication, then fail
            if (_options.AuthenticationOptions.EnableLocalLogin == false ||
                _validatedRequest.Client.EnableLocalLogin == false)
            {
                LogError("EnableLocalLogin is disabled, failing with UnsupportedGrantType");
                return Invalid(Constants.NativeLoginErrors.UnsupportedGrantType);
            }

            /////////////////////////////////////////////
            // check if client is authorized for grant type
            /////////////////////////////////////////////
            if (!_validatedRequest.Client.AllowedCustomGrantTypes.Contains(Constants.GrantTypes.DomainNative))
            {
                LogError("Client not authorized for domain native flow");
                return Invalid(Constants.NativeLoginErrors.UnauthorizedClient);
            }

            /////////////////////////////////////////////
            // check if client is allowed to request scopes
            /////////////////////////////////////////////
            if (!await ValidateRequestedScopesAsync(parameters))
            {
                LogError("Invalid scopes.");
                return Invalid(Constants.NativeLoginErrors.InvalidScope);
            }


            var connectType = parameters.Get(Constants.NativeLoginRequest.Connect);
            var connectCode = parameters.Get(Constants.NativeLoginRequest.ConnectChallenge);
            var connectSessionCode = parameters.Get(Constants.NativeLoginRequest.ConnectSessionCode);
            var userName = parameters.Get(Constants.TokenRequest.UserName);
            var redirectUri = parameters.Get(Constants.TokenRequest.RedirectUri);

            if (connectType.IsMissing())
            {
                LogError("connect is missing.");
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            if (AllowedConnectTypes.All(c => c != connectType))
            {
                LogError("connect type is invalid.");
                return Invalid(Constants.NativeLoginErrors.InvalidConnectType);
            }

            if (connectType == Constants.NativeLoginRequest.ConnectTypes.Email || 
                connectType == Constants.NativeLoginRequest.ConnectTypes.MobilePhone)
            {
                if (userName.IsMissing())
                {
                    LogError("username is missing for passworldless connect type.");
                    return Invalid(Constants.NativeLoginErrors.UsernameMissing);
                }

                if (connectType == Constants.NativeLoginRequest.ConnectTypes.Email)
                {
                    if (redirectUri.IsMissing())
                    {
                        LogError("Redirect URI is missing.");
                        return Invalid(Constants.TokenErrors.UnauthorizedClient);
                    }

                    //////////////////////////////////////////////////////////
                    // check if redirect_uri is valid
                    //////////////////////////////////////////////////////////
                    if (await _uriValidator.IsRedirectUriValidAsync(redirectUri, _validatedRequest.Client) == false)
                    {
                        LogError("Invalid redirect_uri: " + redirectUri);
                        return Invalid("The redirect URI in the request, " + redirectUri + ", does not match the ones authorized for the OAuth client.");
                    }
                }
            }
            else
            {
                if (connectSessionCode.IsMissing())
                {
                    LogError("auth code is missing.");
                    return Invalid(Constants.NativeLoginErrors.InvalidGrant);
                }

                if (connectSessionCode.Length > _options.InputLengthRestrictions.AuthorizationCode)
                {
                    LogError("auth code too long.");
                    return Invalid(Constants.NativeLoginErrors.InvalidGrant);
                }

                if (connectCode.IsMissing() && connectType != Constants.NativeLoginRequest.ConnectTypes.Otp)
                {
                    LogError("connect code missing.");
                    return Invalid(Constants.NativeLoginErrors.InvalidConnectChallenge);
                }
            }


            _validatedRequest.PasswordlessConnect = connectType;
            _validatedRequest.PasswordlessConnectCode = connectCode;
            _validatedRequest.PasswordlessOtp = connectSessionCode;

            /////////////////////////////////////////////
            // check optional parameters and populate SignInMessage
            /////////////////////////////////////////////
            var signInMessage = new SignInMessage();

            // pass through client_id
            signInMessage.ClientId = _validatedRequest.Client.ClientId;
            signInMessage.ReturnUrl = redirectUri;

            // process acr values
            var acr = parameters.Get(Constants.AuthorizeRequest.AcrValues);
            if (acr.IsPresent())
            {
                if (acr.Length > _options.InputLengthRestrictions.AcrValues)
                {
                    LogError("Acr values too long.");
                    return Invalid(Constants.NativeLoginErrors.InvalidRequest);
                }

                var acrValues = acr.FromSpaceSeparatedString().Distinct().ToList();

                // look for well-known acr value -- idp
                var idp = acrValues.FirstOrDefault(x => x.StartsWith(Constants.KnownAcrValues.HomeRealm));
                if (idp.IsPresent())
                {
                    signInMessage.IdP = idp.Substring(Constants.KnownAcrValues.HomeRealm.Length);
                    acrValues.Remove(idp);
                }

                // look for well-known acr value -- tenant
                var tenant = acrValues.FirstOrDefault(x => x.StartsWith(Constants.KnownAcrValues.Tenant));
                if (tenant.IsPresent())
                {
                    signInMessage.Tenant = tenant.Substring(Constants.KnownAcrValues.Tenant.Length);
                    acrValues.Remove(tenant);
                }

                // pass through any remaining acr values
                if (acrValues.Any())
                {
                    signInMessage.AcrValues = acrValues;
                }
            }

            _validatedRequest.SignInMessage = signInMessage;
            

            /////////////////////////////////////////////
            // authenticate user
            /////////////////////////////////////////////
            var authenticationContext = new LocalAuthenticationContext
            {
                PasswordlessConnectType = connectType,
                PasswordlessConnectCode = connectCode,           
                PasswordlessSessionCode = connectSessionCode,
                SignInMessage = signInMessage,
                UserName = userName
            };

            await _users.AuthenticateLocalAsync(authenticationContext);
            var authnResult = authenticationContext.AuthenticateResult;

            var error = Resources.Messages.InvalidPasswordlessCodes;

            if (authnResult != null && authnResult.FailedAuthentication)
            {
                LogError("User authentication failed: " + authnResult.ErrorMessage);

                if (authnResult.HasSubject)
                {
                    await RaiseFailedDomainNativeAuthenticationEventAsync(authnResult.User.GetSubjectId(), signInMessage, authnResult.ErrorMessage);
                }

                return Unauthorized(authnResult.ErrorMessage);
            }

            if (authnResult == null || authnResult.IsError)
            {
                if (authnResult != null && authnResult.IsError)
                {
                    LogError("User authentication failed: " + authnResult.ErrorMessage);
                    if (authnResult.HasSubject)
                    {
                        await RaiseFailedDomainNativeAuthenticationEventAsync(authnResult.User.GetSubjectId(), signInMessage, authnResult.ErrorMessage);
                    }
                }

                if (authnResult != null)
                {
                    return authnResult.AuthenticationFailureCode == AuthenticationFailedCode.None ? Invalid(error, authnResult.ErrorMessage) : Invalid(authnResult.AuthenticationFailureCode.ToString(),authnResult.ErrorMessage);
                }

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            _validatedRequest.IsPartiallyAuthenticated = authnResult.IsPartialSignIn;
            _validatedRequest.Subject = authnResult.User;


            Logger.Info("Password native log request validation success.");

            if (authnResult.IsPartialSignIn)
            {
                _validatedRequest.PartialReason = authnResult.PartialSignInReason;
                _validatedRequest.PasswordlessOtp = authenticationContext.PasswordlessSessionCode;
                await RaiseNativePartialLoginSuccessEventAsync(authnResult.User.Identities.First(), signInMessage);

                return Partial(authnResult.PartialSignInReason);
            }

            await RaiseNativeLoginSuccessEventAsync(_validatedRequest.UserName, signInMessage, authnResult);

            return Valid();
        }

        private async Task<NativeLoginRequestValidationResult> ValidateRefreshTokenRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start validation of refresh token request");

            var refreshTokenHandle = parameters.Get(Constants.TokenRequest.RefreshToken);
            if (refreshTokenHandle.IsMissing())
            {
                var error = "Refresh token is missing";
                LogError(error);
                await RaiseRefreshTokenRefreshFailureEventAsync(null, error);

                return Invalid(Constants.NativeLoginErrors.InvalidRequest);
            }

            if (refreshTokenHandle.Length > _options.InputLengthRestrictions.RefreshToken)
            {
                var error = "Refresh token too long";
                LogError(error);
                await RaiseRefreshTokenRefreshFailureEventAsync(null, error);

                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            _validatedRequest.RefreshTokenHandle = refreshTokenHandle;

            /////////////////////////////////////////////
            // check if refresh token is valid
            /////////////////////////////////////////////
            var refreshToken = await _refreshTokens.GetAsync(refreshTokenHandle);
            if (refreshToken == null)
            {
                var error = "Refresh token is invalid";
                LogWarn(error);
                await RaiseRefreshTokenRefreshFailureEventAsync(refreshTokenHandle, error);

                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            /////////////////////////////////////////////
            // check if refresh token has expired
            /////////////////////////////////////////////
            if (refreshToken.CreationTime.HasExceeded(refreshToken.LifeTime))
            {
                var error = "Refresh token has expired";
                LogWarn(error);
                await RaiseRefreshTokenRefreshFailureEventAsync(refreshTokenHandle, error);

                await _refreshTokens.RemoveAsync(refreshTokenHandle);
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            /////////////////////////////////////////////
            // check if client belongs to requested refresh token
            /////////////////////////////////////////////
            if (_validatedRequest.Client.ClientId != refreshToken.ClientId)
            {
                LogError(string.Format("Client {0} tries to refresh token belonging to client {1}", _validatedRequest.Client.ClientId, refreshToken.ClientId));
                await RaiseRefreshTokenRefreshFailureEventAsync(refreshTokenHandle, "Invalid client binding");

                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            /////////////////////////////////////////////
            // check if client still has offline_access scope
            /////////////////////////////////////////////
            if (!_validatedRequest.Client.AllowAccessToAllScopes)
            {
                if (!_validatedRequest.Client.AllowedScopes.Contains(Constants.StandardScopes.OfflineAccess))
                {
                    var error = "Client does not have access to offline_access scope anymore";
                    LogError(error);
                    await RaiseRefreshTokenRefreshFailureEventAsync(refreshTokenHandle, error);

                    return Invalid(Constants.NativeLoginErrors.InvalidGrant);
                }
            }

            /////////////////////////////////////////////
            // check if client still has access to 
            // all scopes from the original token request
            /////////////////////////////////////////////
            if (!_validatedRequest.Client.AllowAccessToAllScopes)
            {
                foreach (var scope in refreshToken.Scopes)
                {
                    if (!_validatedRequest.Client.AllowedScopes.Contains(scope))
                    {
                        var error = "Client does not have access to a requested scope anymore: " + scope;
                        LogError(error);
                        await RaiseRefreshTokenRefreshFailureEventAsync(refreshTokenHandle, error);

                        return Invalid(Constants.NativeLoginErrors.InvalidGrant);
                    }
                }
            }

            _validatedRequest.RefreshToken = refreshToken;

            /////////////////////////////////////////////
            // make sure user is enabled
            /////////////////////////////////////////////
            var principal = IdentityServerPrincipal.FromSubjectId(_validatedRequest.RefreshToken.SubjectId, refreshToken.AccessToken.Claims);

            var isActiveCtx = new IsActiveContext(principal, _validatedRequest.Client);
            await _users.IsActiveAsync(isActiveCtx);

            if (isActiveCtx.IsActive == false)
            {
                var error = "User has been disabled: " + _validatedRequest.RefreshToken.SubjectId;
                LogError(error);
                await RaiseRefreshTokenRefreshFailureEventAsync(refreshTokenHandle, error);

                return Invalid(Constants.NativeLoginErrors.InvalidRequest);
            }

            /////////////////////////////////////////////
            // validate token type and PoP parameters if pop token is requested
            /////////////////////////////////////////////
            var tokenType = parameters.Get("token_type");
            if (tokenType != null && tokenType == "pop")
            {
                var result = ValidatePopParameters(parameters);
                if (result.IsError)
                {
                    var error = "PoP parameter validation failed: " + result.ErrorDescription;
                    LogError(error);
                    await RaiseRefreshTokenRefreshFailureEventAsync(refreshTokenHandle, error);

                    return Invalid(result.Error, result.ErrorDescription);
                }
                else
                {
                    _validatedRequest.RequestedTokenType = RequestedTokenTypes.PoP;
                }
            }

            Logger.Info("Validation of refresh token request success");
            return Valid();
        }        

        private async Task<bool> ValidateRequestedScopesAsync(NameValueCollection parameters)
        {
            var scopes = parameters.Get(Constants.TokenRequest.Scope);
            if (scopes.IsMissingOrTooLong(_options.InputLengthRestrictions.Scope))
            {
                Logger.Warn("Scopes missing or too long");
                return false;
            }

            var requestedScopes = ScopeValidator.ParseScopesString(scopes);

            if (requestedScopes == null)
            {
                return false;
            }

            if (!_scopeValidator.AreScopesAllowed(_validatedRequest.Client, requestedScopes))
            {
                return false;
            }

            if (!await _scopeValidator.AreScopesValidAsync(requestedScopes))
            {
                return false;
            }

            _validatedRequest.Scopes = requestedScopes;
            _validatedRequest.ValidatedScopes = _scopeValidator;
            return true;
        }

        private NativeLoginRequestValidationResult ValidateAuthorizationCodeWithProofKeyParameters(string codeVerifier, AuthorizationCode authZcode)
        {
            if (authZcode.CodeChallenge.IsMissing() || authZcode.CodeChallengeMethod.IsMissing())
            {
                LogError("Client uses AuthorizationCodeWithProofKey flow but missing code challenge or code challenge method in authZ code");
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            if (codeVerifier.IsMissing())
            {
                LogError("Missing code_verifier");
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            if (codeVerifier.Length < _options.InputLengthRestrictions.CodeVerifierMinLength ||
                codeVerifier.Length > _options.InputLengthRestrictions.CodeVerifierMaxLength)
            {
                LogError("code_verifier is too short or too long.");
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            if (Constants.SupportedCodeChallengeMethods.Contains(authZcode.CodeChallengeMethod) == false)
            {
                LogError("Unsupported code challenge method: " + authZcode.CodeChallengeMethod);
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            if (ValidateCodeVerifierAgainstCodeChallenge(codeVerifier, authZcode.CodeChallenge, authZcode.CodeChallengeMethod) == false)
            {
                LogError("Transformed code verifier does not match code challenge");
                return Invalid(Constants.NativeLoginErrors.InvalidGrant);
            }

            return Valid();
        }

        private bool ValidateCodeVerifierAgainstCodeChallenge(string codeVerifier, string codeChallenge, string codeChallengeMethod)
        {
            if (codeChallengeMethod == Constants.CodeChallengeMethods.Plain)
            {
                return TimeConstantComparer.IsEqual(codeVerifier.Sha256(), codeChallenge);
            }

            var codeVerifierBytes = Encoding.ASCII.GetBytes(codeVerifier);
            var hashedBytes = codeVerifierBytes.Sha256();
            var transformedCodeVerifier = Base64Url.Encode(hashedBytes);

            return TimeConstantComparer.IsEqual(transformedCodeVerifier.Sha256(), codeChallenge);
        }

        private NativeLoginRequestValidationResult ValidatePopParameters(NameValueCollection parameters)
        {
            var invalid = new NativeLoginRequestValidationResult
            {
                IsError = true,
                Error = Constants.NativeLoginErrors.InvalidRequest
            };

            // check optional alg
            var alg = parameters.Get(Constants.TokenRequest.Algorithm);
            if (alg != null)
            {
                // for now we only support asymmetric
                if (!Constants.AllowedProofKeyAlgorithms.Contains(alg))
                {
                    invalid.ErrorDescription = "invalid alg.";
                    return invalid;
                }

                _validatedRequest.ProofKeyAlgorithm = alg;
            }

            // key is required - for now we only support client generated keys
            var key = parameters.Get(Constants.TokenRequest.Key);
            if (key == null)
            {
                invalid.ErrorDescription = "key is required.";
                return invalid;
            }
            if (key.Length > _options.InputLengthRestrictions.ProofKey)
            {
                invalid.ErrorDescription = "invalid key.";
                Logger.Warn("Proof key exceeds max allowed length.");
                return invalid;
            }

            var jwk = string.Format("{{ \"jwk\":{0} }}", Encoding.UTF8.GetString(Base64Url.Decode(key)));
            _validatedRequest.ProofKey = jwk;

            return new NativeLoginRequestValidationResult { IsError = false };
        }

        private NativeLoginRequestValidationResult Valid()
        {
            return new NativeLoginRequestValidationResult
            {
                IsError = false
            };
        }

        private NativeLoginRequestValidationResult Partial(string reason)
        {
            return new NativeLoginRequestValidationResult
            {
                IsError = false,
                PartialReason = reason
            };
        }

        private NativeLoginRequestValidationResult Invalid(string error)
        {
            return new NativeLoginRequestValidationResult
            {
                IsError = true,
                Error = error
            };
        }

        private NativeLoginRequestValidationResult Unauthorized(string error)
        {
            return new NativeLoginRequestValidationResult
            {
                UnauthorizedReason = error,                
            };
        }

        private NativeLoginRequestValidationResult Invalid(string error, string errorDescription)
        {
            return new NativeLoginRequestValidationResult
            {
                IsError = true,
                Error = error,
                ErrorDescription = errorDescription
            };
        }

        private void LogError(string message)
        {
            Logger.Error(LogEvent(message));
        }

        private void LogInfo(string message)
        {
            Logger.Info(LogEvent(message));
        }

        private void LogWarn(string message)
        {
            Logger.Warn(LogEvent(message));
        }

        private void LogSuccess()
        {
            Logger.Info(LogEvent("Token request validation success"));
        }

        private Func<string> LogEvent(string message)
        {
            return () =>
            {
                var validationLog = new NativeLoginRequestValidationLog(_validatedRequest);
                var json = LogSerializer.Serialize(validationLog);

                return string.Format("{0}\n {1}", message, json);
            };
        }

        private async Task RaiseSuccessfulResourceOwnerAuthenticationEventAsync(string userName, string subjectId, SignInMessage signInMessage)
        {
            await _events.RaiseSuccessfulResourceOwnerFlowAuthenticationEventAsync(userName, subjectId, signInMessage);
        }

        private async Task RaiseFailedResourceOwnerAuthenticationEventAsync(string userName, SignInMessage signInMessage, string error)
        {
            await _events.RaiseFailedResourceOwnerFlowAuthenticationEventAsync(userName, signInMessage, error);
        }

        private async Task RaiseFailedDomainNativeAuthenticationEventAsync(string userName, SignInMessage signInMessage, string error)
        {
            await _events.RaiseFailedDomainNativeFlowAuthenticationEventAsync(userName, signInMessage, error);
        }

        private async Task RaiseNativeLoginSuccessEventAsync(string userName, SignInMessage signInMessage, AuthenticateResult result)
        {
            await _events.RaiseNativeSuccessEventAsync(userName, signInMessage, result);
        }

        private async Task RaiseNativePartialLoginSuccessEventAsync(ClaimsIdentity subject, SignInMessage signInMessage)
        {
            await _events.RaiseNativePartialLoginSuccessEventAsync(subject, signInMessage);
        }

        private async Task RaiseFailedAuthorizationCodeRedeemedEventAsync(string handle, string error)
        {
            await _events.RaiseFailedAuthorizationCodeRedeemedEventAsync(_validatedRequest.Client, handle, error);
        }

        private async Task RaiseSuccessfulAuthorizationCodeRedeemedEventAsync()
        {
            await _events.RaiseSuccessAuthorizationCodeRedeemedEventAsync(_validatedRequest.Client, _validatedRequest.AuthorizationCodeHandle);
        }

        private async Task RaiseRefreshTokenRefreshFailureEventAsync(string handle, string error)
        {
            await _events.RaiseFailedRefreshTokenRefreshEventAsync(_validatedRequest.Client, handle, error);
        }
    }
}