using System;
using System.Text;
using System.Threading.Tasks;
using DesCrypto;
using Kerberos.Lib;
using Kerberos.Lib.Models;
using Serilog;
using Serilog.Events;

namespace ConsoleApp
{
    class Program
    {
        private const string Login = "client";
        private const string Password = "clientpassword";
        private const string ServerName = "server";

        static Task Main(string[] args)
        {
            return DoWork();
        }

        static async Task DoWork()
        {
            var kdcClient = new KdcClient();

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .Enrich.FromLogContext()
                .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Debug)
                .CreateLogger();

            Log.Information("Sending a registration request with login '{Login}' and password '{Password}'", Login, Password);
            await kdcClient.Register(Login, Password);
            var mainKey = KeyManager.GenerateSessionKey(Password);
            Log.Information("Generated a [Client <-> AuthServer] key based on password. Key: {Key}", Encoding.UTF8.GetString(mainKey));

            Log.Information("Step #1. Send an authentication request with login '{Login}'", Login);
            var authEncrypted = await kdcClient.Authenticate(Login);
            Log.Information("Step #2.1. Bytes received from Authentication Server: {Bytes}", Encoding.UTF8.GetString(authEncrypted));
            var authResponse = Des.Decrypt<AuthResponse>(mainKey, authEncrypted);
            Log.Information("Step #2.2. Decrypting incoming bytes using [Client <-> AuthServer] key. Authentication Response: {@AuthResponse}", authResponse);

            var tgsKey = authResponse.Key;
            Log.Information("Step #2.3. Got a key that will be used for [Clien <-> TGS] conversation. Key: {Key}", Encoding.UTF8.GetString(tgsKey));

            var authBlock = new AuthBlock { Login = Login, Timestamp = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds() };
            var encryptedAuthBlock = Des.Encrypt(tgsKey, authBlock);
            var ticketRequest = new AuthRequest
            {
                EncryptedTicket = authResponse.EncryptedTicket,
                EncryptedAuthBlock = encryptedAuthBlock,
                Recepient = ServerName
            };
            Log.Information("Step #3.1. Making up a Ticket Request message to send to the Ticket Granting Server. Decrypted Auth Block: {@AuthBlock}", authBlock);
            Log.Information("Step #3.2. Ticket Request: {@TicketRequest}", ticketRequest);

            authEncrypted = await kdcClient.RequestTicket(ticketRequest);
            Log.Information("Step #4.1. Bytes received from Ticket Granting Server: {Bytes}", Encoding.UTF8.GetString(authEncrypted));
            authResponse = Des.Decrypt<AuthResponse>(tgsKey, authEncrypted);
            Log.Information("Step #4.2. Decrypting incoming bytes using [Client <-> TGS] key. TGS Response: {@AuthResponse}", authResponse);

            var serverKey = authResponse.Key;
            Log.Information("Received a session key for [server <-> client] conversation");

            authBlock.Timestamp = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds();
            encryptedAuthBlock = Des.Encrypt(serverKey, authBlock);
            Log.Information("Step #5.1. Using the [server <-> client] session key to encrypt the renewed auth block: {@AuthBlock}", authBlock);
            var authRequest = new AuthRequest
            {
                EncryptedTicket = authResponse.EncryptedTicket,
                EncryptedAuthBlock = encryptedAuthBlock,
                Recepient = ServerName
            };
            Log.Information("Step #5.2. Building the auth request for the server: {@AuthRequest}", authRequest);

            Log.Information("Step #5.3. Sending the request to the server");
            var serverResponse = await kdcClient.AuthOnServer(authRequest);
            Log.Information("Step #6.1. Received {Length} bytes from the server, trying to decrypt", serverResponse.Length);

            var timestamp = Des.Decrypt<TimestampWrapper>(serverKey, serverResponse).Timestamp;
            Log.Information("Step #6.2. Decrypted the timestamp using the [server <-> client] session key: {Timestamp}", timestamp);

            if (timestamp - 1 != authBlock.Timestamp) 
            {
                Log.Error("Server's timestamp didn't pass the verification. Client's: {T1}, Server's: {T2}", authBlock.Timestamp, timestamp);
                return;
            }
            Log.Information("Step #6.3. Server's identity verified. Client's: {T1}, Server's: {T2}", authBlock.Timestamp, timestamp);
            Log.Information("==== \n\nSuccess! Safe connection has been established. Now [client <-> server] conversation can be continued using the session key: {Key}", Encoding.UTF8.GetString(serverKey));

            return;
        }
    }
}
