using Kerberos.Lib;
using Microsoft.AspNetCore.Builder;
using Serilog;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace Server.Extensions
{
    public static class AppBuilderExtensions
    {
        public static async Task<IApplicationBuilder> RegisterAtKdc(this IApplicationBuilder app)
        {
            var client = new KdcClient();
            Log.Information("Sending a registration request with login '{Login}', password '{password}'", Credentials.Login, Credentials.Password);
            await client.Register(Credentials.Login, Credentials.Password);

            var key = KeyManager.GenerateSessionKey(Credentials.Password);
            var keyManager = app.ApplicationServices.GetService<KeyManager>();
            keyManager.Keys.Add(Credentials.Login, key);
            Log.Information("Generated a [Server <-> AuthServer] key based on password. Key: {Key}", Encoding.UTF8.GetString(key));

            return app;
        }
    }
}
