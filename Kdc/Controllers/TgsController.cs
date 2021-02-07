using DesCrypto;
using Kerberos.Lib;
using Kerberos.Lib.Models;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using System;
using System.Text;

namespace Kdc.Controllers
{
    [ApiController]
    public class TgsController : ControllerBase
    {
        private readonly KeyManager _keyManager;
        
        public TgsController(KeyManager keyManager)
        {
            _keyManager = keyManager;
        }

        [Route("tgs")]
        public IActionResult GrantTicket(AuthRequest request)
        {
            Log.Information("Step #3. Received a Ticket Grant request: {@Request}", request);
            var tgsKey = _keyManager.Keys["tgs"];

            if (!_keyManager.Keys.TryGetValue(request.Recepient, out var recepientKey))
            {
                Log.Error("Requested recepient '{Recepient}' was not registered yet", request.Recepient);
                throw new ArgumentException();
            }
            Log.Information("Step #4.1. Found requested recepient '{Recepient}' in the registered list with key {Key}", request.Recepient, Encoding.UTF8.GetString(recepientKey));

            var ticketGrantingTicket = Des.Decrypt<Ticket>(tgsKey, request.EncryptedTicket);
            Log.Information("Step #4.2. Decrypted the Ticket Granting Ticket using the [AuthServer <-> TGS] key: {@Ticket}", ticketGrantingTicket);

            var clientToTgsKey = ticketGrantingTicket.Key;
            Log.Information("Step #4.3. Got a session key ['{Login}' <-> TGS] from TGT: {Key}", ticketGrantingTicket.From, Encoding.UTF8.GetString(ticketGrantingTicket.Key));

            var authBlock = Des.Decrypt<AuthBlock>(clientToTgsKey, request.EncryptedAuthBlock);
            Log.Information("Step #4.4. Decrypted the Auth Block using ['{Login}' <-> TGS] key: {@AuthBlock}", authBlock.Login, authBlock);

            if (!ticketGrantingTicket.From.Equals(authBlock.Login, System.StringComparison.OrdinalIgnoreCase)
                || ticketGrantingTicket.Timestamp + ticketGrantingTicket.Expiration < authBlock.Timestamp)
            {
                Log.Warning("Names in two blocks are not equal or the TGT has expired");
                return NotFound();
            }
            Log.Information("Step #4.5. Verified the data of two blocks and the ticket expiration time");

            var ticket = new Ticket
            {
                From = authBlock.Login,
                To = request.Recepient,
                Key = KeyManager.GenerateSessionKey(),
                Timestamp = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds(),
                Expiration = 300
            };
            Log.Information("Step #4.6. Build new ticket with newly generated session key [{From} <-> {To}]: {@Ticket}", ticket.From, ticket.To, ticket);

            var authResponse = new AuthResponse
            {
                EncryptedTicket = Des.Encrypt(recepientKey, ticket),
                Key = ticket.Key
            };
            Log.Information("Step #4.7. Encrypt the ticket using [Auth Server <-> {To}] key and pack it up into the response: {@Response}", ticket.To, authResponse);

            var encryptedResponse = Des.Encrypt(clientToTgsKey, authResponse);
            Log.Information("Step #4.8. Encrypt the message before sending using the [{From} <-> TGS] key", ticket.From);

            return Ok(Convert.ToBase64String(encryptedResponse));
        }
    }
}
