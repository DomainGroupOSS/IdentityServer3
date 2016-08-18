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
    internal class NativeLoginUnauthorizedResult : IHttpActionResult
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        public string Reason { get; internal set; }
        public string ReasonDescription { get; internal set; }

        public NativeLoginUnauthorizedResult(string reason)
        {
            Reason = reason;
        }

        public NativeLoginUnauthorizedResult(string reason, string reasonDescription)
        {
            Reason = reason;
            ReasonDescription = reasonDescription;
        }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }

        private HttpResponseMessage Execute()
        {
            var dto = new ErrorDto
            {
                error = Reason,
                error_description = ReasonDescription
            };

            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new ObjectContent<ErrorDto>(dto, new JsonMediaTypeFormatter())
            };

            Logger.Info("Returning error: " + Reason);
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