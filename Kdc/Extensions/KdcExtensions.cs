using Kerberos.Lib;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Kdc.Extensions
{
    public static class KdcExtensions
    {
        public const string TgsName = "tgs";

        public static IApplicationBuilder RegisterTgs(this IApplicationBuilder app)
        {
            var keyManager = app.ApplicationServices.GetService<KeyManager>();
            keyManager.Keys.Add(TgsName, KeyManager.GenerateSessionKey());

            return app;
        }
    }
}
