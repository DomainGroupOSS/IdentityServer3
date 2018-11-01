/*
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

using FluentAssertions;
using IdentityModel;
using IdentityServer3.Core;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.ResponseHandling;
using IdentityServer3.Core.Services.Default;
using IdentityServer3.Core.Validation;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading.Tasks;
using IdentityServer3.Core.Services.InMemory;
using Xunit;
using IdentityServer3.Core.Extensions;

namespace IdentityServer3.Tests.Connect.ResponseHandling
{

    public class AuthorizeInteractionResponseGeneratorTests_Login
    {
        IdentityServerOptions options;

        public AuthorizeInteractionResponseGeneratorTests_Login()
        {
            options = new IdentityServerOptions();
        }

        [Fact]
        public async Task Anonymous_User_must_SignIn()
        {
            var generator = new AuthorizeInteractionResponseGenerator(options, null, null, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo"
            };

            var result = await generator.ProcessLoginAsync(request, Principal.Anonymous);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Authenticated_User_must_not_SignIn()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client()
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.IsLogin.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_With_MultiFactor_Request_must_SignIn()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var acrValues = new List<string>(){"FirstACRValue", Constants.KnownAcrValues.MultiFactor, "thirdAcrValue"};
            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                AuthenticationContextReferenceClasses = acrValues,
                Raw = new NameValueCollection { { Constants.AuthorizeRequest.AcrValues, acrValues.ToSpaceSeparatedString() }}
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Request_with_multiFactor_acr_should_return_signimessage_having_PromptAuthenticatedUserFor2FA_property_set_to_true_if_AuthenticatedUser_exists()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var acrValues = new List<string>() { $"FirstACRValue", {Constants.KnownAcrValues.MultiFactor}, "thirdAcrValue" };
            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                AuthenticationContextReferenceClasses = acrValues,
                Raw = new NameValueCollection { { Constants.AuthorizeRequest.AcrValues, acrValues.ToSpaceSeparatedString()} }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.SignInMessage.PromptAuthenticatedUserFor2FA.Should().BeTrue();
        }


        [Fact]
        public async Task Request_with_multiFactor_acr_should_return_signin_message_having_PromptAuthenticatedUserFor2FA_property_set_set_to_false_if_AuthenticatedUser_does_not_exists()
        {
            var users = new List<InMemoryUser>() { };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                Raw = new NameValueCollection { { Constants.AuthorizeRequest.AcrValues, $"FirstACRValue {Constants.KnownAcrValues.MultiFactor} thirdAcrValue" } }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.SignInMessage.PromptAuthenticatedUserFor2FA.Should().BeFalse();
        }

        [Fact]
        public async Task Request_with_Signup_acr_value_should_be_updated_to_not_have_the_Signup_acr_value()
        {
            var users = new List<InMemoryUser>() { };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var originalAcrValues = new List<string>() { "FirstACRValue", Constants.KnownAcrValues.Signup, "thirdAcrValue" };
            var updatedAcrValue = $"FirstACRValue thirdAcrValue";
            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                AuthenticationContextReferenceClasses = originalAcrValues,
                Raw = new NameValueCollection { { Constants.AuthorizeRequest.AcrValues, originalAcrValues.ToSpaceSeparatedString() } }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            await generator.ProcessLoginAsync(request, principal);

            request.Raw.GetValues(Constants.AuthorizeRequest.AcrValues).Should().Equal(updatedAcrValue);
        }


        [Fact]
        public async Task Request_with_multiFactor_acr_should_be_updated_to_not_have_the_multiFactor_acr_if_AuthenticatedUser_exists()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var originalAcrValues = new List<string>() { "FirstACRValue", Constants.KnownAcrValues.MultiFactor, "thirdAcrValue" };
            var updatedAcrValue = $"FirstACRValue thirdAcrValue";
            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                AuthenticationContextReferenceClasses = originalAcrValues,
                Raw = new NameValueCollection { { Constants.AuthorizeRequest.AcrValues, originalAcrValues.ToSpaceSeparatedString() } }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            await generator.ProcessLoginAsync(request, principal);

            request.Raw.GetValues(Constants.AuthorizeRequest.AcrValues).Should().Equal(updatedAcrValue);
        }

        [Fact]
        public async Task Request_with_multiFactor_acr_should_not_be_updated_if_AuthenticatedUser_does_not_exists()
        {
            var users = new List<InMemoryUser>() {  };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var originalAcrValue = $"FirstACRValue {Constants.KnownAcrValues.MultiFactor} thirdAcrValue";
            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                Raw = new NameValueCollection { { Constants.AuthorizeRequest.AcrValues, originalAcrValue } }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom", authenticationTime: 12);
            await generator.ProcessLoginAsync(request, principal);

            request.Raw.GetValues(Constants.AuthorizeRequest.AcrValues).Should().Equal(originalAcrValue);
        }

        [Fact]
        public async Task Request_with_multiFactor_acr_should_return_signimessage_having_PromptAuthenticatedUserFor2FA_property_set_to_false_if_AuthenticatedUser_exists_but_Email_Verification_is_Required()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: true);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                Raw = new NameValueCollection { { Constants.AuthorizeRequest.AcrValues, $"FirstACRValue {Constants.KnownAcrValues.MultiFactor} thirdAcrValue" } }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.SignInMessage.PromptAuthenticatedUserFor2FA.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_Requiring_Email_Verification_must_SignIn()
        {
            var users = new List<InMemoryUser>() {new InMemoryUser() {Subject = "123", Enabled = true}};
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification:true);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client()
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Authenticated_User_Not_Requiring_Email_Verification_must_not_SignIn()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification:false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client()
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.IsLogin.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_with_allowed_current_Idp_must_not_SignIn()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Subject = IdentityServerPrincipal.Create("123", "dom"),
                Client = new Client 
                {
                    IdentityProviderRestrictions = new List<string> 
                    {
                        Constants.BuiltInIdentityProvider
                    }
                }
            };

            var result = await generator.ProcessClientLoginAsync(request);

            result.IsLogin.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_with_restricted_current_Idp_must_SignIn()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Subject = IdentityServerPrincipal.Create("123", "dom"),
                Client = new Client
                {
                    IdentityProviderRestrictions = new List<string> 
                    {
                        "some_idp"
                    }
                }
            };

            var result = await generator.ProcessClientLoginAsync(request);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Authenticated_User_with_allowed_requested_Idp_must_not_SignIn()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                 AuthenticationContextReferenceClasses = new List<string>{
                    "idp:" + Constants.BuiltInIdentityProvider
                }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.IsLogin.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_with_different_requested_Idp_must_SignIn()
        {
            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Client = new Client(),
                AuthenticationContextReferenceClasses = new List<string>{
                    "idp:some_idp"
                },
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessLoginAsync(request, principal);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Authenticated_User_with_local_Idp_must_SignIn_when_global_options_does_not_allow_local_logins()
        {
            options.AuthenticationOptions.EnableLocalLogin = false;

            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Subject = IdentityServerPrincipal.Create("123", "dom"),
                Client = new Client
                {
                    ClientId = "foo",
                    EnableLocalLogin = true
                }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessClientLoginAsync(request);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Authenticated_User_with_local_Idp_must_SignIn_when_client_options_does_not_allow_local_logins()
        {
            options.AuthenticationOptions.EnableLocalLogin = true;

            var users = new List<InMemoryUser>() { new InMemoryUser() { Subject = "123", Enabled = true } };
            var userService = new InMemoryUserServiceTest(users, allUsersRequireEmailVerification: false);
            var generator = new AuthorizeInteractionResponseGenerator(options, null, userService, null, new DefaultLocalizationService());

            var request = new ValidatedAuthorizeRequest
            {
                ClientId = "foo",
                Subject = IdentityServerPrincipal.Create("123", "dom"),
                Client = new Client
                {
                    ClientId = "foo",
                    EnableLocalLogin = false
                }
            };

            var principal = IdentityServerPrincipal.Create("123", "dom");
            var result = await generator.ProcessClientLoginAsync(request);

            result.IsLogin.Should().BeTrue();
        }
    }

    public class InMemoryUserServiceTest : InMemoryUserService
    {
        private bool _allUsersRequireEmailVerification;
        public InMemoryUserServiceTest(List<InMemoryUser> users, bool allUsersRequireEmailVerification) : base(users)
        {
            _allUsersRequireEmailVerification = allUsersRequireEmailVerification;
        }

        public override Task IsActiveAsync(IsActiveContext context)
        {
            base.IsActiveAsync(context);
            context.IsEmailVerificationRequired = _allUsersRequireEmailVerification;
            return Task.FromResult(0);
        }
    }

}
