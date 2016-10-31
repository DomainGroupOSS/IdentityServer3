using System;
using System.Collections.Specialized;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;
using IdentityServer3.Tests.TokenClients;
using IdentityServer3.Tests.TokenClients.Setup;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Xunit;

namespace IdentityServer3.Tests.Validation
{
    public class NativeLoginRequestValidation
    {
        public NativeLoginRequestValidation()
        {
            _validatorSetup = new NativeLoginRequestValidatorTestSetup();
            _parameters = new PasswordlessTestParameters();
            _client = new PasswordlessTestClient();
        }

        private const string Category = "Validation - Native Login Request Validation Tests";

        private readonly NativeLoginRequestValidatorTestSetup _validatorSetup;
        private readonly PasswordlessTestParameters _parameters;
        private readonly PasswordlessTestClient _client;

        [Fact]
        public async void Client_Does_Not_Contain_DomainNative_GrantType_Return_Unauthorized_On_Passwordless()
        {
            _validatorSetup.InitializeValidator();
            _client.UnauthorizeDomainNativeGrantType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_parameters, _client);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnauthorizedClient);
        }

        [Fact]
        public async void Disabled_Local_Authentication_Should_Return_Error_Result_On_Passwordless()
        {
            _validatorSetup.DisableLocalAuthentication();
            _client.DisableLocalLogin();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_parameters, _client);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        [Fact]
        public async void Empty_Client_Should_Throw_Argument_Null_Exception()
        {
            Client client = null;
            _validatorSetup.InitializeValidator();

            Func<Task> act = async () => { await _validatorSetup.Validator.ValidateRequestAsync(_parameters, client); };

            act.ShouldThrow<ArgumentNullException>();
        }

        [Fact]
        public async void Empty_Parameters_Should_Throw_Argument_Null_Exception()
        {
            NameValueCollection parameters = null;
            _validatorSetup.InitializeValidator();

            Func<Task> act = async () => { await _validatorSetup.Validator.ValidateRequestAsync(parameters, _client); };

            act.ShouldThrow<ArgumentNullException>();
        }

        [Fact]
        public async void GrantType_Too_Long_Should_Return_Error_Result()
        {
            _validatorSetup.InitializeValidator();
            _parameters.ChangeToLongGrantType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_parameters, _client);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        [Fact]
        public async void Invalid_Scopes_Passed_Return_Error_On_Passwordless()
        {
            _validatorSetup.ScopeValidatorReturnsInvalid();
            _validatorSetup.InitializeValidator();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_parameters, _client);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidScope);
        }

        [Fact]
        public async void Missing_GrantType_Should_Return_Error_Result()
        {
            _validatorSetup.InitializeValidator();
            _parameters.RemoveGrantType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_parameters, _client);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.UnsupportedGrantType);
        }

        [Fact]
        public async void Missing_ConnectType_ReturnError_On_Passwordless()
        {
            _validatorSetup.ScopeValidatorReturnsValid();
            _validatorSetup.InitializeValidator();
            _parameters.RemoveConnectType();

            var result = await _validatorSetup.Validator.ValidateRequestAsync(_parameters, _client);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be(Constants.NativeLoginErrors.InvalidGrant);
        }

        [Fact]
        [Ignore]
        public async Task Valid_Passwordless_Native_Request_Returns_Valid()
        {
            
        }
    }
}