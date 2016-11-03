using System.Collections.Specialized;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using IdentityServer3.Core.Configuration.Hosting;
using IdentityServer3.Core.Events;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.ResponseHandling;
using IdentityServer3.Core.Results;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Validation;

namespace IdentityServer3.Core.Endpoints
{
    [SecurityHeaders]
    [NoCache]
    [PreventUnsupportedRequestMediaTypes(allowFormUrlEncoded: true)]
    internal class NativeAuthenticationController : ApiController
    {
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();
        private readonly ClientSecretValidator _clientValidator;
        private readonly IEventService _eventService;
        private readonly NativeLoginRequestValidator _requestValidator;
        private readonly NativeLoginResponseGenerator _responseGenerator;


        public NativeAuthenticationController(
            IEventService eventService,
            ClientSecretValidator clientValidator,
            NativeLoginRequestValidator requestValidator,
            NativeLoginResponseGenerator responseGenerator)
        {
            _eventService = eventService;
            _clientValidator = clientValidator;
            _requestValidator = requestValidator;
            _responseGenerator = responseGenerator;
        }

        [Route(Constants.RoutePaths.DomainOidc.LoginNative)]
        [HttpPost]
        public async Task<IHttpActionResult> Post()
        {
            Logger.Info("Native login submitted");

            var response = await ProcessAsync(await Request.GetOwinContext().ReadRequestFormAsNameValueCollectionAsync());

            if (response is NativeLoginErrorResult)
            {
                var details = response as NativeLoginErrorResult;
                await RaiseFailureEventAsync(details.Error);
            }
            else
            {
                await _eventService.RaiseSuccessfulEndpointEventAsync(EventConstants.EndpointNames.NativeLogin);
            }

            Logger.Info("End native login request");
            return response;
        }

        public async Task<IHttpActionResult> ProcessAsync(NameValueCollection parameters)
        {
            // validate client credentials and client
            var clientResult = await _clientValidator.ValidateAsync();
            if (clientResult.IsError)
            {
                return this.NativeLoginErrorResponse(Constants.NativeLoginErrors.InvalidClient);
            }

            var requestResult = await _requestValidator.ValidateRequestAsync(parameters, clientResult.Client);

            if (requestResult.IsUnauthorized)
            {
                return this.NativeLoginUnauthorizedResponse(requestResult.UnauthorizedReason, requestResult.UnauthorizedReasonDescription);
            }

            if (requestResult.IsError)
            {
                return this.NativeLoginErrorResponse(requestResult.Error, requestResult.ErrorDescription);
            }
            
            // return response
            var response = await _responseGenerator.ProcessAsync(_requestValidator.ValidatedRequest);
            return this.NativeLoginResponse(response);
        }

        private async Task RaiseFailureEventAsync(string error)
        {
            await _eventService.RaiseFailureEndpointEventAsync(EventConstants.EndpointNames.NativeLogin, error);
        }
    }
}