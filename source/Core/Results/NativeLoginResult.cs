using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace IdentityServer3.Core.Results
{
    internal class NativeLoginResult : IHttpActionResult
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();
        private readonly static JsonSerializer Serializer = new JsonSerializer
        {
            DefaultValueHandling = DefaultValueHandling.Ignore,
            NullValueHandling = NullValueHandling.Ignore
        };

        private readonly NativeLoginResponse _response;

        public NativeLoginResult(NativeLoginResponse response)
        {
            _response = response;
        }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }

        private HttpResponseMessage Execute()
        {
            var dto = new NativeLoginResponseDto
            {
                id_token = _response.IdentityToken,
                access_token = _response.AccessToken,
                refresh_token = _response.RefreshToken,
                expires_in = _response.AccessTokenLifetime,
                token_type = _response.TokenType,
                alg = _response.Algorithm
            };

            var jobject = JObject.FromObject(dto, Serializer);

            // custom entries
            if (_response.Custom != null && _response.Custom.Any())
            {
                foreach (var item in _response.Custom)
                {
                    JToken token;
                    if (jobject.TryGetValue(item.Key, out token))
                    {
                        throw new Exception("Item does already exist - cannot add it via a custom entry: " + item.Key);
                    }

                    jobject.Add(new JProperty(item.Key, item.Value));
                }
            }

            var status = _response.IsPartial ? HttpStatusCode.Forbidden : HttpStatusCode.OK;

            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(jobject.ToString(), Encoding.UTF8, "application/json")
            };

            Logger.Info("Returning token response.");
            return response;
        }

        internal class NativeLoginResponseDto
        {
            public string id_token { get; set; }
            public string access_token { get; set; }
            public int expires_in { get; set; }
            public string token_type { get; set; }
            public string refresh_token { get; set; }
            public string alg { get; set; }
        }
    }

    internal class NativeLoginPartialResult : IHttpActionResult
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();
        private readonly static JsonSerializer Serializer = new JsonSerializer
        {
            DefaultValueHandling = DefaultValueHandling.Ignore,
            NullValueHandling = NullValueHandling.Ignore
        };

        private readonly NativeLoginResponse _response;

        public NativeLoginPartialResult(NativeLoginResponse response)
        {
            _response = response;
        }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }

        private HttpResponseMessage Execute()
        {
            var dto = new NativeLoginResponseDto
            {
                id_token = _response.IdentityToken,
                expires_in = _response.AccessTokenLifetime,
                token_type = _response.TokenType,
                alg = _response.Algorithm
            };

            var jobject = JObject.FromObject(dto, Serializer);

            // custom entries
            if (_response.Custom != null && _response.Custom.Any())
            {
                foreach (var item in _response.Custom)
                {
                    JToken token;
                    if (jobject.TryGetValue(item.Key, out token))
                    {
                        throw new Exception("Item does already exist - cannot add it via a custom entry: " + item.Key);
                    }

                    jobject.Add(new JProperty(item.Key, item.Value));
                }
            }

            var response = new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent(jobject.ToString(), Encoding.UTF8, "application/json")
            };

            Logger.Info("Returning partial login response.");
            return response;
        }

        internal class NativeLoginResponseDto
        {
            public string id_token { get; set; }
            public int expires_in { get; set; }
            public string token_type { get; set; }
            public string alg { get; set; }
        }
    }
}