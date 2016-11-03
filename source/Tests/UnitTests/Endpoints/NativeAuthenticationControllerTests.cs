using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Web;
using System.Web.SessionState;
using IdentityServer3.Core;
using IdentityServer3.Core.Endpoints;
using IdentityServer3.Core.Models;
using IdentityServer3.Tests.TokenClients.Setup;
using Microsoft.Owin;
using Xunit;

namespace IdentityServer3.Tests.Endpoints
{
    public class NativeAuthenticationControllerTests : IdSvrHostTestBase
    {
        private HttpResponseMessage PostNativeEndpoint(NameValueCollection parameters)
        {
            return PostForm(Constants.RoutePaths.DomainOidc.LoginNative, parameters);
        }

        [Fact]
        public void Test()
        {
            var testParameters = new PasswordlessTestParameters();
            testParameters.AddClient(TestClients.Get().FirstOrDefault(c => c.ClientId == "client"));

            //TODO: still returning error
            PostNativeEndpoint(testParameters);
        }
    }
}