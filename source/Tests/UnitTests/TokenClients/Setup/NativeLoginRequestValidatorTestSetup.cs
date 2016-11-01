using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Validation;
using Moq;

namespace IdentityServer3.Tests.TokenClients.Setup
{
    public class NativeLoginRequestValidatorTestSetup
    {
        public NativeLoginRequestValidatorTestSetup()
        {
            Options = new IdentityServerOptions();
            AuthorizationCodeStoreMock = new Mock<IAuthorizationCodeStore>();
            RefreshTokenStoreMock = new Mock<IRefreshTokenStore>();
            CustomGrantValidatorMock = new Mock<ICustomGrantValidator>();
            UserServiceMock = new Mock<IUserService>();
            ScopeStoreMock = new Mock<IScopeStore>();
            EventServiceMock = new Mock<IEventService>();
            TwoFactorServiceMock = new Mock<ITwoFactorService>();
            RedirectUrlValidatorMock = new Mock<IRedirectUriValidator>();
            ScopeValidatorMock = new Mock<IScopeValidator>();
        }

        internal NativeLoginRequestValidator Validator { get; set; }
        internal IdentityServerOptions Options { get; set; }
        internal Mock<IAuthorizationCodeStore> AuthorizationCodeStoreMock { get; set; }
        internal Mock<IRefreshTokenStore> RefreshTokenStoreMock { get; set; }
        internal Mock<ICustomGrantValidator> CustomGrantValidatorMock { get; set; }
        internal Mock<IUserService> UserServiceMock { get; set; }
        internal Mock<IScopeStore> ScopeStoreMock { get; set; }
        internal Mock<IEventService> EventServiceMock { get; set; }
        internal Mock<ITwoFactorService> TwoFactorServiceMock { get; set; }
        internal Mock<IRedirectUriValidator> RedirectUrlValidatorMock { get; set; }
        public Mock<IScopeValidator> ScopeValidatorMock { get; set; }

        public void InitializeValidator()
        {
            var grantValidator = new Core.Validation.CustomGrantValidator(new[] {CustomGrantValidatorMock.Object});

            Validator = new NativeLoginRequestValidator(Options, AuthorizationCodeStoreMock.Object,
                RefreshTokenStoreMock.Object, UserServiceMock.Object, grantValidator, ScopeValidatorMock.Object,
                EventServiceMock.Object, TwoFactorServiceMock.Object, RedirectUrlValidatorMock.Object);
        }

        public void DisableLocalAuthentication()
        {
            Options.AuthenticationOptions.EnableLocalLogin = false;
        }

        public void ScopeValidatorReturnsValid()
        {
            ScopeValidatorMock.Setup(y => y.AreScopesAllowed(It.IsAny<Client>(), It.IsAny<List<string>>())).Returns(true);
            ScopeValidatorMock.Setup(y => y.AreScopesValidAsync(It.IsAny<List<string>>())).Returns(Task.FromResult(true));
        }

        public void ScopeValidatorReturnsInvalid()
        {
            ScopeValidatorMock.Setup(y => y.AreScopesAllowed(It.IsAny<Client>(), It.IsAny<List<string>>())).Returns(false);
            ScopeValidatorMock.Setup(y => y.AreScopesValidAsync(It.IsAny<List<string>>())).Returns(Task.FromResult(false));
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
                context.AuthenticateResult.PartialSignInReason = "test successful partial reason";
                context.PasswordlessSessionCode = context.PasswordlessSessionCode;
            }).Returns(Task.FromResult(true));
        }
    }
}