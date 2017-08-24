using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;
using IdentityServer3.Tests.TokenClients;
using IdentityServer3.Tests.TokenClients.Setup;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Xunit;

namespace IdentityServer3.Tests.Validation
{
    public class NativeLoginRequestValidation
    {
        public NativeLoginRequestValidation()
        {
            _validatorSetup = new NativeLoginRequestValidatorTestSetup();
            _passwordlessTestParameters = new PasswordlessTestParameters();
            _passwordlessTestClient = new PasswordlessTestClient();
            _authorizationCodeTestClient = new AuthorizationCodeTestClient();
            _authorizationCodeTestParameters = new AuthorizationCodeTestParameters();
            _resourceOwnerTestClient = new ResourceOwnerTestClient();
            _resourceOwnerTestParameters = new ResourceOwnerTestParameters();
            _refreshTokenTestClient = new RefreshTokenTestClient();
            _refreshTokenTestParameters = new RefreshTokenTestParameters();
        }

        private const string Category = "Validation - Native Login Request Validation Tests";

        private readonly NativeLoginRequestValidatorTestSetup _validatorSetup;
        private readonly PasswordlessTestParameters _passwordlessTestParameters;
        private readonly PasswordlessTestClient _passwordlessTestClient;
        private readonly AuthorizationCodeTestClient _authorizationCodeTestClient;
        private readonly AuthorizationCodeTestParameters _authorizationCodeTestParameters;
        private readonly ResourceOwnerTestClient _resourceOwnerTestClient;
        private readonly ResourceOwnerTestParameters _resourceOwnerTestParameters;
        private readonly RefreshTokenTestClient _refreshTokenTestClient;
        private readonly RefreshTokenTestParameters _refreshTokenTestParameters;

        [Fact]
        public async void Unsupported_Grant_Type_Returns_Invalid()
        {
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(new NameValueCollection
            {
                {Constants.TokenRequest.GrantType, Constants.GrantTypes.JwtBearer}
            }, new Client
            {
                ClientId = "empty-test"
            });

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        [Fact]
        public async void Client_Does_Not_Contain_DomainNative_GrantType_Return_Unauthorized_On_Authorization_Code()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.UnauthorizeDomainNativeGrantType();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnauthorizedClient);
        }

        [Fact]
        public async void Missing_Code_Should_Throw_Invalid_Grant_On_Authorization_Code()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestParameters.RemoveCode();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Code_Too_Long_Should_Throw_Invalid_Grant_On_Authorization_Code()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestParameters.ChangeToLongCode();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Authorization_Code_Is_Not_Found_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Different_Client_Id_Passed_To_Request_From_Authorization_Code_Store()
        {
            _validatorSetup.InitializeValidator();
            var testClient = new Client
            {
                AllowedCustomGrantTypes = { Constants.GrantTypes.DomainNative, Constants.GrantTypes.AuthorizationCode },
                AllowedScopes = { "read" },
                ClientId = "test-different-client-name",
            };

            var code = new TestAuthorizationCode(testClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void AuthorizationCodeWithProofKey_Missing_Code_Challenge_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToAuthorizationCodeWithProofKey();
            
            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.RemoveCodeChallenge();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);
            
            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void HybridWithProofKey_Missing_Code_Challenge_Should_Throw_Invalid_Grant_On_Authorization_Code()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToHybridWithProofKey();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.RemoveCodeChallenge();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void AuthorizationCodeWithProofKey_Missing_Code_Challenge_Method_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToAuthorizationCodeWithProofKey();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.RemoveCodeChallengeMethod();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void HybridWithProofKey_Missing_Code_Challenge_Method_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToHybridWithProofKey();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.RemoveCodeChallengeMethod();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void AuthorizationCodeWithProofKey_Missing_Code_Verifier_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToAuthorizationCodeWithProofKey();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }
        
        [Fact]
        public async void HybridWithProofKey_Missing_Code_Verifier_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToHybridWithProofKey();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void AuthorizationCodeWithProofKey_Code_Verifier_Too_Long_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToAuthorizationCodeWithProofKey();
            _authorizationCodeTestParameters.SetToLongCodeVerifier();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void HybridWithProofKey_Code_Verifier_Too_Long_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToHybridWithProofKey();
            _authorizationCodeTestParameters.SetToLongCodeVerifier();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void AuthorizationCodeWithProofKey_Code_Challenge_Method_Not_Supported_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToAuthorizationCodeWithProofKey();
            _authorizationCodeTestParameters.SetDefaultCodeVerifier();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.SetCodeChallengeMethodToRandom();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void HybridWithProofKey_Code_Challenge_Method_Not_Supported_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToHybridWithProofKey();
            _authorizationCodeTestParameters.SetDefaultCodeVerifier();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.SetCodeChallengeMethodToRandom();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void AuthorizationCodeWithProofKey_Plain_Code_Challenge_Is_Not_Validated_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToAuthorizationCodeWithProofKey();
            _authorizationCodeTestParameters.SetDefaultCodeVerifier();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.SetToWrongCodeChallenge();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void HybridWithProofKey_Plain_Code_Challenge_Is_Not_Validated_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestClient.SetFlowToHybridWithProofKey();
            _authorizationCodeTestParameters.SetDefaultCodeVerifier();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.SetToWrongCodeChallenge();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Code_Verifier_Presents_At_Non_AuthCodeWithProof_And_HybridWithProof_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestParameters.SetDefaultCodeVerifier();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Expired_AuthCode_Should_Throw_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.SetToOldCreationtime();

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);


            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Missing_Redirect_Uri_Should_Throw_Unauthorized_Client_On_Authorization_Code()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestParameters.RemoveRedirectUri();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.TokenErrors.UnauthorizedClient);
        }

        [Fact]
        public async void Wrong_Redirect_Uri_Should_Throw_Unauthorized_Client_On_Authorization_Code()
        {
            _validatorSetup.InitializeValidator();
            _authorizationCodeTestParameters.SetToWrongRedirectUri();
            _authorizationCodeTestClient.RemoveAuthorizationCodeFromAllowedGrantType();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Contain("https://test.domain.com.au");
        }

        [Fact]
        public async void Missing_Requested_Scopes_Should_Throw_Invalid_Request_On_Authorization_Code()
        {
            _validatorSetup.InitializeValidator();
            
            var code = new TestAuthorizationCode(_authorizationCodeTestClient);
            code.RemoveDefaultRequestedScopes();
            
            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.TokenErrors.InvalidRequest);
        }

        [Fact]
        public async void Disabled_Account_Should_Throw_Invalid_Request_On_Authorization_Code()
        {
            _validatorSetup.UserIsActiveReturnsFalse();
            _validatorSetup.InitializeValidator();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.TokenErrors.InvalidRequest);
        }

        [Fact]
        public async void Valid_Request_On_Authorization_Code()
        {
            _validatorSetup.UserIsActiveReturnsTrue();
            _validatorSetup.InitializeValidator();

            var code = new TestAuthorizationCode(_authorizationCodeTestClient);

            await _validatorSetup.SetDefaultAuthorizationCodeStore(code);

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_authorizationCodeTestParameters,
                        _authorizationCodeTestClient);

            result.IsError.Should().BeFalse();
        }

        [Fact]
        public async void Disabled_Local_Authentication_Should_Return_Error_Result_On_Resource_Owner()
        {
            _validatorSetup.DisableLocalAuthentication();
            _resourceOwnerTestClient.DisableLocalLogin();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        [Fact]
        public async void Unauthorized_Client_Grant_Type_Throws_Unauthorized_Client_On_Resource_Owner()
        {
            _validatorSetup.InitializeValidator();
            _resourceOwnerTestClient.RemoveDomainNative();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnauthorizedClient);
        }

        [Fact]
        public async void Invalid_Requested_Scopes_On_Resource_Owner()
        {
            _validatorSetup.InitializeValidator();
            _resourceOwnerTestParameters.SetScopeToInvalid();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidScope);
        }

        [Fact]
        public async void Missing_Username_Throws_Invalid_Grant_On_Resource_Owner()
        {
            _validatorSetup.InitializeValidator();
            _resourceOwnerTestParameters.RemoveUsername();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Missing_Password_Throws_Invalid_Grant_On_Resource_Owner()
        {
            _validatorSetup.InitializeValidator();
            _resourceOwnerTestParameters.RemovePassword();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Long_Username_Throws_Invalid_Grant_On_Resource_Owner()
        {
            _validatorSetup.InitializeValidator();
            _resourceOwnerTestParameters.ChangeToLongUsername();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Long_Password_Throws_Invalid_Grant_On_Resource_Owner()
        {
            _validatorSetup.InitializeValidator();
            _resourceOwnerTestParameters.ChangeToLongPassword();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Invalid_User_Authentication_Should_Throw_Invalid_Grant_On_Resource_Owner()
        {
            _validatorSetup.UserAuthenticateLocalReturnsInvalid();
            _validatorSetup.InitializeValidator();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters,
                        _resourceOwnerTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Core.Resources.Messages.InvalidUsernameOrPassword);
        }

        [Fact]
        public async void Valid_Partial_Request_With_2FA_On_Resource_Owner()
        {
            _validatorSetup.UserAuthenticateLocalReturnsPartial();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);
            
            result.IsError.Should().BeFalse();
            result.IsPartial.Should().BeTrue();

            _validatorSetup.TwoFactorServiceMock.Verify(m => m.RequestCodeAsync(_resourceOwnerTestClient, It.IsAny<ClaimsPrincipal>()), Times.AtLeastOnce);
        }

        [Fact]
        public async void Valid_Request_On_Resource_Owner()
        {
            _validatorSetup.UserAuthenticateLocalReturnsValid();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_resourceOwnerTestParameters, _resourceOwnerTestClient);

            result.IsError.Should().BeFalse();
        }

        [Fact]
        public async void Missing_Refresh_Token_Should_Throw_InvalidRequest()
        {
            _validatorSetup.InitializeValidator();
            _refreshTokenTestParameters.RemoveRefreshToken();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidRequest);
        }

        [Fact]
        public async void Refresh_Token_Too_Long_Returns_Invalid_Grant()
        {
            _validatorSetup.InitializeValidator();
            _refreshTokenTestParameters.ChangeToLongRefreshToken();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Invalid_Refresh_Token_Should_Throw_Invalid_Grant()
        {
            var testRefreshToken = new TestRefreshToken(_refreshTokenTestClient);
            
            await _validatorSetup.SetDefaultRefreshTokenStore(testRefreshToken);
            _refreshTokenTestParameters.ChangeToInvalidRefreshToken();
            _validatorSetup.InitializeValidator();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Expired_Refresh_Token_Should_Throw_Invalid_Grant()
        {
            var testRefreshToken = new TestRefreshToken(_refreshTokenTestClient);
            testRefreshToken.SetCreationTimeToExpired();

            await _validatorSetup.SetDefaultRefreshTokenStore(testRefreshToken);
            _validatorSetup.InitializeValidator();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Invalid_Client_On_Refresh_Token_Should_Throw_Invalid_Grant()
        {
            var testRefreshToken = new TestRefreshToken(new Client
            {
                AllowedCustomGrantTypes = { Constants.GrantTypes.DomainNative, Constants.GrantTypes.RefreshToken },
                AllowedScopes = { "read" },
                ClientId = "test-different-client-name",
            });

            await _validatorSetup.SetDefaultRefreshTokenStore(testRefreshToken);
            _validatorSetup.InitializeValidator();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Missing_Offline_Scope_Should_Throw_Invalid_Grant_On_Refresh_Token()
        {
            var testRefreshToken = new TestRefreshToken(_refreshTokenTestClient);

            await _validatorSetup.SetDefaultRefreshTokenStore(testRefreshToken);
            _validatorSetup.InitializeValidator();

            _refreshTokenTestClient.RemoveOfflineAccessScope();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Invalid_Requested_Scopes_Should_Throw_Invalid_Grant_On_Refresh_Token()
        {
            var testRefreshToken = new TestRefreshToken(_refreshTokenTestClient, new List<Claim>
            {
                new Claim("scope", "read"),
                new Claim("scope", Constants.StandardScopes.OfflineAccess),
                new Claim("scope", "invalid"),
                new Claim(Constants.ClaimTypes.Subject, "test-subject-id")
            });

            await _validatorSetup.SetDefaultRefreshTokenStore(testRefreshToken);


            _validatorSetup.InitializeValidator();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Disabled_User_Should_Throw_Invalid_Request_On_Refresh_Token()
        {
            var testRefreshToken = new TestRefreshToken(_refreshTokenTestClient);

            await _validatorSetup.SetDefaultRefreshTokenStore(testRefreshToken);
            _validatorSetup.UserIsActiveReturnsFalse();
            _validatorSetup.InitializeValidator();
            
            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidRequest);
        }

        [Fact]
        public async void Valid_Refresh_Token_Request()
        {
            var testRefreshToken = new TestRefreshToken(_refreshTokenTestClient);

            await _validatorSetup.SetDefaultRefreshTokenStore(testRefreshToken);
            _validatorSetup.UserIsActiveReturnsTrue();
            _validatorSetup.InitializeValidator();

            var result =
                await
                    _validatorSetup.Validator.ValidateRequestAsync(_refreshTokenTestParameters, _refreshTokenTestClient);

            result.IsError.Should().BeFalse();
        }

        [Fact]
        public async void Client_Does_Not_Contain_DomainNative_GrantType_Return_Unauthorized_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestClient.UnauthorizeDomainNativeGrantType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnauthorizedClient);
        }

        [Fact]
        public async void Disabled_Local_Authentication_Should_Return_Error_Result_On_Passwordless()
        {
            _validatorSetup.DisableLocalAuthentication();
            _passwordlessTestClient.DisableLocalLogin();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        [Fact]
        public async void Empty_Client_Should_Throw_Argument_Null_Exception()
        {
            Client client = null;
            _validatorSetup.InitializeValidator();

            Func<Task> act = async () => { await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, client); };

            act.ShouldThrow<ArgumentNullException>();
        }

        [Fact]
        public async void Empty_Parameters_Should_Throw_Argument_Null_Exception()
        {
            NameValueCollection parameters = null;
            _validatorSetup.InitializeValidator();

            Func<Task> act = async () => { await _validatorSetup.Validator.ValidateRequestAsync(parameters, _passwordlessTestClient); };

            act.ShouldThrow<ArgumentNullException>();
        }

        [Fact]
        public async void GrantType_Too_Long_Should_Return_Error_Result()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.ChangeToLongGrantType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        [Fact]
        public async void Invalid_Scopes_Passed_Return_Error_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.ChangeToInvalidScope();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidScope);
        }

        [Fact]
        public async void Missing_GrantType_Should_Return_Error_Result()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.RemoveGrantType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        [Fact]
        public async void Missing_ConnectType_Return_Error_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.RemoveConnectType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Invalid_ConnectType_Return_Error_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.ChangeToInvalidConnectType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidConnectType);
        }

        [Fact]
        public async void Missing_Username_Email_ConnectType_Return_Error_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.ChangeToEmailConnectType();
            _passwordlessTestParameters.RemoveUsername();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UsernameMissing);
        }

        [Fact]
        public async void Missing_RedirectUri_Email_ConnectType_Return_Error_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.ChangeToEmailConnectType();
            _passwordlessTestParameters.RemoveRedirectUri();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnauthorizedClient);
        }

        [Fact]
        public async void Invalid_RedirectUri_Email_ConnectType_Return_Error_On_Passwordless()
        {
            _validatorSetup.RedirectUriValidatorReturnsInvalid();
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.ChangeToEmailConnectType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Contain("http://localhost");
        }

        [Fact]
        public async void Missing_Username_MobilePhone_ConnectType_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.ChangeToMobilePhoneConnectType();
            _passwordlessTestParameters.RemoveUsername();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UsernameMissing);
        }

        [Fact]
        public async void Missing_ConnectSessionCode_Return_Error_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.RemoveSessionCode();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Long_ConnectSessionCode_Return_Error_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.ChangeToLongSessionCode();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        public async void Missing_ConnectCode_ReturnError_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _passwordlessTestParameters.RemoveConnectCode();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidConnectChallenge);
        }

        [Fact]
        public async void Invalid_User_Credentials_Return_Error_On_Passwordless()
        {
            _validatorSetup.UserAuthenticateLocalReturnsInvalid();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.UnauthorizedReason.Should().Be(Core.Resources.Messages.InvalidUsernameOrPassword);
        }

        [Fact]
        public async void Empty_User_Credentials_Return_Error_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.TokenErrors.InvalidGrant);
        }

        [Fact]
        public async void Valid_Partial_Login_Request_On_Passwordless()
        {
            _validatorSetup.UserAuthenticateLocalReturnsPartial();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);


            result.IsError.Should().BeFalse();
            result.IsPartial.Should().BeTrue();
        }

        [Fact]
        public async void Valid_Passwordless_Native_Request_Returns_Valid()
        {
            _validatorSetup.UserAuthenticateLocalReturnsValid();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_passwordlessTestParameters, _passwordlessTestClient);

            result.IsError.Should().BeFalse();
        }
    }
}