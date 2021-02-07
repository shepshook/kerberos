using DesCrypto;
using Kerberos.Lib;
using Kerberos.Lib.Models;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using System;

namespace Server.Controllers
{
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly KeyManager _keyManager;

        public AuthController(KeyManager keyManager)
        {
            _keyManager = keyManager;
        }

        [Route("auth")]
        public IActionResult Auth(AuthRequest request)
        {
            Log.Information("Step #5.1. Received an authentication request: {@Request}", request);
            var tgsKey = _keyManager.Keys[Credentials.Login];

            var ticket = Des.Decrypt<Ticket>(tgsKey, request.EncryptedTicket);
            Log.Information("Step #5.2. Decrypted the ticket using the [server <-> TGS] key: {@Ticket}", ticket);

            var clientKey = ticket.Key;
            var authBlock = Des.Decrypt<AuthBlock>(clientKey, request.EncryptedAuthBlock);
            Log.Information("Step #5.3. Decrypted the auth block using the [server <-> client] session key: {@AuthBlock}", authBlock);

            if (!ticket.From.Equals(authBlock.Login, System.StringComparison.OrdinalIgnoreCase)
                || ticket.Timestamp + ticket.Expiration < authBlock.Timestamp)
            {
                Log.Warning("Names in two blocks are not equal or the ticket has expired");
                return NotFound();
            }
            Log.Information("Step #5.4. Successfully verified the identity of '{From}'", ticket.From);

            _keyManager.Keys.Add(ticket.From, clientKey);
            Log.Information("Step #5.5. Stored the session key for [server <-> client] conversation");

            var timestamp = authBlock.Timestamp + 1;
            Log.Information("Step #6.1. Incrementing the timestamp value by 1 to prove the server's identity: {Timestamp}", timestamp);

            var timestampWrapper = new TimestampWrapper { Timestamp = timestamp };
            var encryptedTimestamp = Des.Encrypt(clientKey, timestampWrapper);
            Log.Information("Step #6.2. Encrypting timestamp using the [server <-> client] session key");
            Log.Information("Step #6.3. Sending encrypted timestamp back to client");

            return Ok(Convert.ToBase64String(encryptedTimestamp));
        }
    }
}
