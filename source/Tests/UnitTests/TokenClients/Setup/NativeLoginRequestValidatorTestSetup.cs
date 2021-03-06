﻿using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityServer3.Core;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Services.InMemory;
using IdentityServer3.Core.Validation;
using IdentityServer3.Tests.Validation;
using Moq;

namespace IdentityServer3.Tests.TokenClients.Setup
{
    public class NativeLoginRequestValidatorTestSetup
    {
        public NativeLoginRequestValidatorTestSetup()
        {
            Options = new IdentityServerOptions();
            AuthorizationCodeStore = new InMemoryAuthorizationCodeStore();
            RefreshTokenStore = new InMemoryRefreshTokenStore();
            CustomGrantValidatorMock = new Mock<ICustomGrantValidator>();
            UserServiceMock = new Mock<IUserService>();
            EventServiceMock = new Mock<IEventService>();
            TwoFactorServiceMock = new Mock<ITwoFactorService>();
            RedirectUrlValidatorMock = new Mock<IRedirectUriValidator>();
            ScopeValidator = new ScopeValidator(new InMemoryScopeStore(TestScopes.Get()));
        }


        internal NativeLoginRequestValidator Validator { get; set; }
        internal IdentityServerOptions Options { get; set; }
        internal InMemoryAuthorizationCodeStore AuthorizationCodeStore { get; set; }
        internal InMemoryRefreshTokenStore RefreshTokenStore { get; set; }
        internal Mock<ICustomGrantValidator> CustomGrantValidatorMock { get; set; }
        internal Mock<IUserService> UserServiceMock { get; set; }
        internal Mock<IEventService> EventServiceMock { get; set; }
        internal Mock<ITwoFactorService> TwoFactorServiceMock { get; set; }
        internal Mock<IRedirectUriValidator> RedirectUrlValidatorMock { get; set; }
        public ScopeValidator ScopeValidator { get; set; }

        public void InitializeValidator()
        {
            var grantValidator = new Core.Validation.CustomGrantValidator(new[] {CustomGrantValidatorMock.Object});

            Validator = new NativeLoginRequestValidator(Options, AuthorizationCodeStore,
                RefreshTokenStore, UserServiceMock.Object, grantValidator, ScopeValidator,
                EventServiceMock.Object, TwoFactorServiceMock.Object, RedirectUrlValidatorMock.Object);
        }

        public async Task SetDefaultAuthorizationCodeStore(AuthorizationCode code)
        {
            await AuthorizationCodeStore.StoreAsync("test-connect-code", code);
        }

        public async Task SetDefaultRefreshTokenStore(RefreshToken refreshToken)
        {
            await RefreshTokenStore.StoreAsync("valid-example-of-refresh-token", refreshToken);
        }

        public void DisableLocalAuthentication()
        {
            Options.AuthenticationOptions.EnableLocalLogin = false;
        }

        public void RedirectUriValidatorReturnsValid()
        {
            RedirectUrlValidatorMock.Setup(y => y.IsRedirectUriValidAsync(It.IsAny<string>(), It.IsAny<Client>())).Returns(Task.FromResult(true));
        }

        public void RedirectUriValidatorReturnsInvalid()
        {
            RedirectUrlValidatorMock.Setup(y => y.IsRedirectUriValidAsync(It.IsAny<string>(), It.IsAny<Client>())).Returns(Task.FromResult(false));
        }

        public void UserAuthenticateLocalReturnsValid()
        {
            UserServiceMock.Setup(y => y.AuthenticateLocalAsync(It.IsAny<LocalAuthenticationContext>())).Callback((LocalAuthenticationContext context) =>
            {
                context.AuthenticateResult = new AuthenticateResult("test-subject-id", "test-name");
            }).Returns(Task.FromResult(true));
        }

        public void UserAuthenticateLocalReturnsInvalid()
        {
            UserServiceMock.Setup(y => y.AuthenticateLocalAsync(It.IsAny<LocalAuthenticationContext>())).Callback((LocalAuthenticationContext context) =>
            {
                context.AuthenticateResult = new AuthenticateResult(AuthenticationFailedCode.InvalidCredentials);
            }).Returns(Task.FromResult(true));
        }

        public void UserAuthenticateLocalReturnsPartial()
        {
            UserServiceMock.Setup(y => y.AuthenticateLocalAsync(It.IsAny<LocalAuthenticationContext>())).Callback((LocalAuthenticationContext context) =>
            {
                context.AuthenticateResult = new AuthenticateResult("/test", "test-subject-id", "test-name");
                context.AuthenticateResult.PartialSignInReason = Constants.NativeLoginPartialReasons.TwoFactorChallengeRequired;
                context.PasswordlessSessionCode = context.PasswordlessSessionCode;
            }).Returns(Task.FromResult(true));
        }

        public void UserIsActiveReturnsTrue()
        {
            UserServiceMock.Setup(y => y.IsActiveAsync(It.IsAny<IsActiveContext>())).Callback(
                (IsActiveContext isActiveContext) =>
                {
                    isActiveContext.IsActive = true;
                }).Returns(Task.FromResult(true));
        }

        public void UserIsActiveReturnsFalse()
        {
            UserServiceMock.Setup(y => y.IsActiveAsync(It.IsAny<IsActiveContext>())).Callback(
                (IsActiveContext isActiveContext) =>
                {
                    isActiveContext.IsActive = false;
                }).Returns(Task.FromResult(true));
        }
    }
}