using Metrics;

namespace IdentityServer3.Core
{
    public static class IdsrvMetrics
    {
        private static readonly string Context = "Idsrv";

        public static void AccessTokenReferenceTokenValidationRatePerClient(string clientid)
        {
            Metric.Context(Context).Meter("access_token validation reference / client_id", Unit.Requests)
                .Mark(new SubItemTagClientIdTag(clientid).ToString());
        }

        public static void AccessTokenJwtTokenValidationRatePerClient(string clientid)
        {
            Metric.Context(Context).Meter("access_token validation jwt / client_id", Unit.Requests)
                .Mark(new SubItemTagClientIdTag(clientid).ToString());
        }

        public static void IdentityTokenValidationRatePerClient(string clientid)
        {
            Metric.Context(Context).Meter("id_token validation jwt / client_id", Unit.Requests)
                .Mark(new SubItemTagClientIdTag(clientid).ToString());
        }
    }
}