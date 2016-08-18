using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using IdentityServer3.Core.Logging;
using Newtonsoft.Json;

namespace IdentityServer3.Core.Results
{
    internal class NativeLoginErrorResult : IHttpActionResult
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        public string Error { get; internal set; }
        public string ErrorDescription { get; internal set; }

        public NativeLoginErrorResult(string error)
        {
            Error = error;
        }

        public NativeLoginErrorResult(string error, string errorDescription)
        {
            Error = error;
            ErrorDescription = errorDescription;
        }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }

        private HttpResponseMessage Execute()
        {
            var dto = new ErrorDto
            {
                error = Error,
                error_description = ErrorDescription
            };

            var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new ObjectContent<ErrorDto>(dto, new JsonMediaTypeFormatter())
            };

            Logger.Info("Returning error: " + Error);
            return response;
        }

        internal class ErrorDto
        {
            public string error { get; set; }
            [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
            public string error_description { get; set; }
        }
    }
}