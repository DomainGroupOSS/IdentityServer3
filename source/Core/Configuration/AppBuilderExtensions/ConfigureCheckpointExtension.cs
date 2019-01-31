using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin
{
    internal class CheckpointMiddleware
    {
        protected readonly Func<IDictionary<string, object>, Task> _next;

        public CheckpointMiddleware(Func<IDictionary<string, object>, Task> next)
        {
            if (next == null)
                throw new ArgumentNullException(nameof(next));

            _next = next;
        }

        public virtual Task Invoke(IDictionary<string, object> environment)
        {
            return _next(environment);
        }
    }

    internal class RequestBodyBufferCheckpointMiddleware : CheckpointMiddleware
    {
        public RequestBodyBufferCheckpointMiddleware(Func<IDictionary<string, object>, Task> next)
            : base(next)
        {
        }

        [NewRelic.Api.Agent.Trace]
        public override Task Invoke(IDictionary<string, object> environment)
        {
            return base.Invoke(environment);
        }
    }

    internal class PostRequestBodyBufferCheckpointMiddleware : CheckpointMiddleware
    {
        public PostRequestBodyBufferCheckpointMiddleware(Func<IDictionary<string, object>, Task> next)
            : base(next)
        {
        }

        [NewRelic.Api.Agent.Trace]
        public override Task Invoke(IDictionary<string, object> environment)
        {
            return base.Invoke(environment);
        }
    }

    internal static class ConfigureCheckpointExtension
    {
        public static IAppBuilder ConfigureRequestBodyBufferCheckpoint(this IAppBuilder app)
        {
            if (app == null) throw new ArgumentNullException("app");

            app.Use<RequestBodyBufferCheckpointMiddleware>();

            return app;
        }

        public static IAppBuilder ConfigurePostRequestBodyBufferCheckpoint(this IAppBuilder app)
        {
            if (app == null) throw new ArgumentNullException("app");

            app.Use<PostRequestBodyBufferCheckpointMiddleware>();

            return app;
        }

    }
}
