using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading.Tasks;
using FluentAssertions;
using FluentAssertions.Common;
using IdentityServer3.Core;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Services.InMemory;
using IdentityServer3.Core.Validation;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Xunit;

namespace IdentityServer3.Tests.Validation
{
    public class NativeLoginRequestValidation
    {
        public NativeLoginRequestValidation()
        {
            _options = new IdentityServerOptions();
            _authorizationCodeStoreMock = new Mock<IAuthorizationCodeStore>();
            _refreshTokenStoreMock = new Mock<IRefreshTokenStore>();
            _customGrantValidatorMock = new Mock<ICustomGrantValidator>();
            _userServiceMock = new Mock<IUserService>();
            _scopeStoreMock = new Mock<IScopeStore>();
            _eventServiceMock = new Mock<IEventService>();
            _twoFactorServiceMock = new Mock<ITwoFactorService>();
            _redirectUrlValidatorMock = new Mock<IRedirectUriValidator>();
            _parameters = new NameValueCollection();
            _client = new Client();
        }

        private const string Category = "Validation - Native Login Request Validation Tests";

        private NativeLoginRequestValidator _validator;
        private IdentityServerOptions _options;
        private NameValueCollection _parameters;
        private Client _client;
        private Mock<IAuthorizationCodeStore> _authorizationCodeStoreMock;
        private Mock<IRefreshTokenStore> _refreshTokenStoreMock;
        private Mock<ICustomGrantValidator> _customGrantValidatorMock;
        private Mock<IUserService> _userServiceMock;
        private Mock<IScopeStore> _scopeStoreMock;
        private Mock<IEventService> _eventServiceMock;
        private Mock<ITwoFactorService> _twoFactorServiceMock;
        private Mock<IRedirectUriValidator> _redirectUrlValidatorMock;


        [Fact, Ignore]
        public async Task Valid_Passwordless_Native_Request_Returns_Valid()
        {
            /*var grantValidator = new CustomGrantValidator(new []{_customGrantValidatorMock.Object});
            var scopeValidator = new Mock<ScopeValidator>();
            scopeValidator.Setup(y=>y.AreScopesAllowed(It.IsAny<Client>(), new List<string>())).Returns(true);
            scopeValidator.Setup(y => y.AreScopesValidAsync(new List<string>())).Returns(Task.FromResult(true));

            _parameters.Add(Constants.TokenRequest.GrantType, Constants.GrantTypes.Passwordless);
            _parameters.Add(Constants.NativeLoginRequest.Connect, Constants.NativeLoginRequest.ConnectTypes.NativeLogin);
            _parameters.Add(Constants.NativeLoginRequest.ConnectChallenge, "test");
            _parameters.Add(Constants.NativeLoginRequest.ConnectSessionCode, "testSessionCode");
            _parameters.Add(Constants.TokenRequest.UserName, "testUsername");
            _parameters.Add(Constants.TokenRequest.UserName, "http://localhost");

            _client.AllowedCustomGrantTypes.Add(Constants.GrantTypes.Passwordless);
            _client.AllowedCustomGrantTypes.Add(Constants.GrantTypes.DomainNative);

            _options.AuthenticationOptions.EnableLocalLogin = true;

            _validator = new NativeLoginRequestValidator(_options, _authorizationCodeStoreMock.Object,
                   _refreshTokenStoreMock.Object, _userServiceMock.Object, grantValidator, scopeValidator.Object,
                   _eventServiceMock.Object, _twoFactorServiceMock.Object, _redirectUrlValidatorMock.Object);

            var result = await _validator.ValidateRequestAsync(_parameters, _client);

            result.IsError.Should().BeFalse();*/
        }

        [Fact]
        public async Task Empty_Client_Should_Throw_Argument_Null_Exception()
        {
            var grantValidator = new CustomGrantValidator(new[] { _customGrantValidatorMock.Object });
            var scopeValidator = new ScopeValidator(_scopeStoreMock.Object);
            Client client = null;

            _validator = new NativeLoginRequestValidator(_options, _authorizationCodeStoreMock.Object,
                   _refreshTokenStoreMock.Object, _userServiceMock.Object, grantValidator, scopeValidator,
                   _eventServiceMock.Object, _twoFactorServiceMock.Object, _redirectUrlValidatorMock.Object);

            Func<Task> act = async () => { await _validator.ValidateRequestAsync(_parameters, client); };
            act.ShouldThrow<ArgumentNullException>();
        }

        [Fact]
        public async Task Empty_Parameters_Should_Throw_Argument_Null_Exception()
        {
            var grantValidator = new CustomGrantValidator(new[] { _customGrantValidatorMock.Object });
            var scopeValidator = new ScopeValidator(_scopeStoreMock.Object);
            NameValueCollection parameters = null;

            _validator = new NativeLoginRequestValidator(_options, _authorizationCodeStoreMock.Object,
                   _refreshTokenStoreMock.Object, _userServiceMock.Object, grantValidator, scopeValidator,
                   _eventServiceMock.Object, _twoFactorServiceMock.Object, _redirectUrlValidatorMock.Object);

            Func<Task> act = async () => { await _validator.ValidateRequestAsync(parameters, _client); };
            act.ShouldThrow<ArgumentNullException>();
        }

        [Fact]
        public async Task Missing_GrantType_Should_Return_Error_Result()
        {
            var grantValidator = new CustomGrantValidator(new[] { _customGrantValidatorMock.Object });
            var scopeValidator = new ScopeValidator(_scopeStoreMock.Object);

            _validator = new NativeLoginRequestValidator(_options, _authorizationCodeStoreMock.Object,
                   _refreshTokenStoreMock.Object, _userServiceMock.Object, grantValidator, scopeValidator,
                   _eventServiceMock.Object, _twoFactorServiceMock.Object, _redirectUrlValidatorMock.Object);

            var result = await _validator.ValidateRequestAsync(_parameters, _client);
            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }
    }
}