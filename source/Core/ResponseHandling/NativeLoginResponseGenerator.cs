using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Validation;
using Newtonsoft.Json;

namespace IdentityServer3.Core.ResponseHandling
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class NativeLoginResponseGenerator
    {
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();

        private readonly ITokenService _tokenService;
        private readonly IRefreshTokenService _refreshTokenService;
        private readonly IScopeStore _scopes;
        private readonly IAuthorizationCodeStore _authorizationCodes;
        private readonly IEventService _eventService;

        public NativeLoginResponseGenerator(ITokenService tokenService, 
            IRefreshTokenService refreshTokenService, 
            IScopeStore scopes, 
            IAuthorizationCodeStore authorizationCodes, 
            IEventService eventService)
        {

            _tokenService = tokenService;
            _refreshTokenService = refreshTokenService;
            _scopes = scopes;
            _authorizationCodes = authorizationCodes;
            _eventService = eventService;
        }

        public async Task<NativeLoginResponse> ProcessAsync(ValidatedNativeLoginRequest request)
        {
            Logger.Info("Creating token response");
            
            NativeLoginResponse response;

            if (request.GrantType == Constants.GrantTypes.AuthorizationCode)
            {
                response = await ProcessAuthorizationCodeRequestAsync(request);
            }
            else if (request.GrantType == Constants.GrantTypes.RefreshToken)
            {
                response = await ProcessRefreshTokenRequestAsync(request);
            }
            else if (request.IsPartiallyAuthenticated)
            {
                response = await ProcessPartialAuthNTokenRequestAsync(request);                
            }
            else
            {
                response = await ProcessTokenRequestAsync(request);
            }
            
            return response;
        }

        private async Task<NativeLoginResponse> ProcessAuthorizationCodeRequestAsync(ValidatedNativeLoginRequest request)
        {
            Logger.Info("Processing authorization code request");

            //////////////////////////
            // access token
            /////////////////////////
            var accessToken = await CreateAccessTokenAsync(request);
            var response = new NativeLoginResponse
            {
                AccessToken = accessToken.Item1,
                AccessTokenLifetime = request.Client.AccessTokenLifetime
            };

            if (request.RequestedTokenType == RequestedTokenTypes.PoP)
            {
                response.TokenType = Constants.ResponseTokenTypes.PoP;
                response.Algorithm = request.ProofKeyAlgorithm;
            }

            //////////////////////////
            // refresh token
            /////////////////////////
            if (accessToken.Item2.IsPresent())
            {
                response.RefreshToken = accessToken.Item2;
            }

            //////////////////////////
            // id token
            /////////////////////////
            if (request.AuthorizationCode.IsOpenId)
            {
                var tokenRequest = new TokenCreationRequest
                {
                    Subject = request.AuthorizationCode.Subject,
                    Client = request.AuthorizationCode.Client,
                    Scopes = request.AuthorizationCode.RequestedScopes,
                    Nonce = request.AuthorizationCode.Nonce,

                    ValidatedRequest = request
                };

                var idToken = await _tokenService.CreateIdentityTokenAsync(tokenRequest);
                var jwt = await _tokenService.CreateSecurityTokenAsync(idToken);
                response.IdentityToken = jwt;
            }

            return response;
        }

        private async Task<NativeLoginResponse> ProcessTokenRequestAsync(ValidatedNativeLoginRequest request)
        {
            Logger.Info("Processing token request");

            var identityToken = await CreateIdentityTokenAsync(request);
            var accessToken = await CreateAccessTokenAsync(request);
            var response = new NativeLoginResponse
            {
                IdentityToken = identityToken,
                AccessToken = accessToken.Item1,
                AccessTokenLifetime = request.Client.AccessTokenLifetime
            };

            if (accessToken.Item2.IsPresent())
            {
                response.RefreshToken = accessToken.Item2;
            }

            return response;
        }

        private async Task<NativeLoginResponse> ProcessPartialAuthNTokenRequestAsync(ValidatedNativeLoginRequest request)
        {
            Logger.Info("Processing native partial login request request");

            var identityToken = await CreatePartialAuthNIdentityTokenAsync(request);
            var response = new NativeLoginResponse
            {
                IdentityToken = identityToken,       
                TokenType = null,
                IsPartial = true
            };

            return response;
        }

        private async Task<NativeLoginResponse> ProcessRefreshTokenRequestAsync(ValidatedNativeLoginRequest request)
        {
            Logger.Info("Processing refresh token request");

            var oldAccessToken = request.RefreshToken.AccessToken;
            string accessTokenString;

            // if pop request, claims must be updated because we need a fresh proof token
            if (request.Client.UpdateAccessTokenClaimsOnRefresh || request.RequestedTokenType == RequestedTokenTypes.PoP)
            {
                var subject = request.RefreshToken.GetOriginalSubject();

                var creationRequest = new TokenCreationRequest
                {
                    Client = request.Client,
                    Subject = subject,
                    ValidatedRequest = request,
                    Scopes = await _scopes.FindScopesAsync(oldAccessToken.Scopes),
                };

                // if pop request, embed proof token
                if (request.RequestedTokenType == RequestedTokenTypes.PoP)
                {
                    creationRequest.ProofKey = GetProofKey(request);
                }

                var newAccessToken = await _tokenService.CreateAccessTokenAsync(creationRequest);
                accessTokenString = await _tokenService.CreateSecurityTokenAsync(newAccessToken);
            }
            else
            {
                var copy = new Token(oldAccessToken);
                copy.CreationTime = DateTimeOffsetHelper.UtcNow;
                copy.Lifetime = request.Client.AccessTokenLifetime;

                accessTokenString = await _tokenService.CreateSecurityTokenAsync(copy);
            }

            var handle = await _refreshTokenService.UpdateRefreshTokenAsync(request.RefreshTokenHandle, request.RefreshToken, request.Client);

            var response = new NativeLoginResponse()
            {
                AccessToken = accessTokenString,
                AccessTokenLifetime = request.Client.AccessTokenLifetime,
                RefreshToken = handle
            };

            if (request.RequestedTokenType == RequestedTokenTypes.PoP)
            {
                response.TokenType = Constants.ResponseTokenTypes.PoP;
                response.Algorithm = request.ProofKeyAlgorithm;
            }

            return response;
        }

        private async Task<Tuple<string, string>> CreateAccessTokenAsync(ValidatedNativeLoginRequest request)
        {
            TokenCreationRequest tokenRequest;
            bool createRefreshToken;

            if (request.AuthorizationCode != null)
            {
                createRefreshToken = request.AuthorizationCode.RequestedScopes.Select(s => s.Name).Contains(Constants.StandardScopes.OfflineAccess);

                tokenRequest = new TokenCreationRequest
                {
                    Subject = request.AuthorizationCode.Subject,
                    Client = request.AuthorizationCode.Client,
                    Scopes = request.AuthorizationCode.RequestedScopes,
                    ValidatedRequest = request
                };
            }
            else
            {
                createRefreshToken = request.ValidatedScopes.ContainsOfflineAccessScope;

                tokenRequest = new TokenCreationRequest
                {
                    Subject = request.Subject,
                    Client = request.Client,
                    Scopes = request.ValidatedScopes.GrantedScopes,
                    ValidatedRequest = request
                };
            }

            // bind proof key to token if present
            if (request.RequestedTokenType == RequestedTokenTypes.PoP)
            {
                tokenRequest.ProofKey = GetProofKey(request);
            }

            Token accessToken = await _tokenService.CreateAccessTokenAsync(tokenRequest);

            string refreshToken = "";
            if (createRefreshToken)
            {
                refreshToken = await _refreshTokenService.CreateRefreshTokenAsync(tokenRequest.Subject, accessToken, request.Client);
            }

            var securityToken = await _tokenService.CreateSecurityTokenAsync(accessToken);
            return Tuple.Create(securityToken, refreshToken);
        }

        private async Task<string> CreatePartialAuthNIdentityTokenAsync(ValidatedNativeLoginRequest request)
        {
            TokenCreationRequest tokenRequest;

            if (request.AuthorizationCode != null)
            {
                tokenRequest = new TokenCreationRequest
                {
                    Subject = request.AuthorizationCode.Subject,
                    Client = request.AuthorizationCode.Client,
                    Scopes = request.AuthorizationCode.RequestedScopes,
                    ValidatedRequest = request
                };
            }
            else
            {
                tokenRequest = new TokenCreationRequest
                {
                    Subject = request.Subject,
                    Client = request.Client,
                    Scopes = request.ValidatedScopes.GrantedScopes,
                    ValidatedRequest = request
                };
            }

            // bind proof key to token if present
            if (request.RequestedTokenType == RequestedTokenTypes.PoP)
            {
                tokenRequest.ProofKey = GetProofKey(request);
            }

            var code = await CreateCodeAsync(request);

            var claims = new List<Claim>();
            claims.AddRange(new []
            {
                new Claim(Constants.ClaimTypes.Partial.Reason, request.PartialReason),
                new Claim(Constants.ClaimTypes.Partial.ConnectSessionCode, code),
            });

            if (request.PartialReason == Constants.NativeLoginPartialReasons.TwoFactorChallengeRequired)
            {
                claims.Add(new Claim(Constants.ClaimTypes.Partial.Connect, Constants.ClaimTypes.Partial.ConnectSms));
            }else if (request.PartialReason.IsPresent())
            {
                claims.Add(new Claim(Constants.ClaimTypes.Partial.Connect, Constants.ClaimTypes.Partial.ConnectWebView));
            }

            var identityToken = await _tokenService.CreatePartialAuthNIdentityTokenAsync(tokenRequest, claims).ConfigureAwait(false);

            return await _tokenService.CreateSecurityTokenAsync(identityToken);
        }

        public virtual async Task<string> CreateCodeAsync(ValidatedNativeLoginRequest request)
        {
            var code = new AuthorizationCode
            {
                Client = request.Client,
                Subject = request.Subject,
                SessionId = request.SessionId,
                CodeChallenge = request.PasswordlessConnectCode.Sha256(),                                
                RequestedScopes = request.ValidatedScopes.GrantedScopes      
            };

            // store id token and access token and return authorization code
            var id = CryptoRandom.CreateUniqueId(32);
            await _authorizationCodes.StoreAsync(id, code);

            await RaiseCodeIssuedEventAsync(id, code);

            return id;
        }

        private async Task RaiseCodeIssuedEventAsync(string id, AuthorizationCode code)
        {
            await _eventService.RaiseAuthorizationCodeIssuedEventAsync(id, code);
        }

        private async Task<string> CreateIdentityTokenAsync(ValidatedNativeLoginRequest request)
        {
            TokenCreationRequest tokenRequest;

            if (request.AuthorizationCode != null)
            {                
                tokenRequest = new TokenCreationRequest
                {
                    Subject = request.AuthorizationCode.Subject,
                    Client = request.AuthorizationCode.Client,
                    Scopes = request.AuthorizationCode.RequestedScopes,
                    ValidatedRequest = request
                };
            }
            else
            {
                tokenRequest = new TokenCreationRequest
                {
                    Subject = request.Subject,
                    Client = request.Client,
                    Scopes = request.ValidatedScopes.GrantedScopes,
                    ValidatedRequest = request
                };
            }

            // bind proof key to token if present
            if (request.RequestedTokenType == RequestedTokenTypes.PoP)
            {
                tokenRequest.ProofKey = GetProofKey(request);
            }

            var identityToken = await _tokenService.CreateIdentityTokenAsync(tokenRequest);

            return await _tokenService.CreateSecurityTokenAsync(identityToken);
        }

        private string GetProofKey(ValidatedNativeLoginRequest request)
        {
            // for now we only support client generated proof keys
            return request.ProofKey;
        }
    }
}