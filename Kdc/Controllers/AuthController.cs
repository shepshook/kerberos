using Microsoft.AspNetCore.Mvc;
using System;
using DesCrypto;
using Kerberos.Lib;
using Kerberos.Lib.Models;
using Serilog;
using System.Text;

namespace Kdc.Controllers
{
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly KeyManager _keyManager;

        public AuthController(KeyManager keyManager)
        {
            _keyManager = keyManager;
        }

        [Route("register")]
        [Consumes("application/x-www-form-urlencoded")]
        public IActionResult Register([FromForm] string login, [FromForm] string password)
        {
            var key = KeyManager.GenerateSessionKey(password);
            _keyManager.Keys.TryAdd(login, key);

            Log.Information("Registered a new KDC user with login '{Login}', password '{Password}' and generated a key {Key}", login, password, Encoding.UTF8.GetString(key));

            return Ok();
        }

        [Route("auth")]
        [Consumes("application/x-www-form-urlencoded")]
        public IActionResult Auth([FromForm] string login)
        {
            Log.Information("Step #1. Received an authentication request from '{Login}'", login);
            if (!_keyManager.Keys.ContainsKey(login))
                return NotFound();

            var sessionKey = KeyManager.GenerateSessionKey();
            Log.Information("Step #2.1. Generate a session key [{Login} <-> TGS]: {Key}", login, Encoding.UTF8.GetString(sessionKey));
            var ticket = new Ticket
            {
                From = login,
                To = "tgs",
                Key = sessionKey,
                Timestamp = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds(),
                Expiration = 3600
            };
            Log.Information("Step #2.2. Make up a Ticket Granting Ticket: {@Ticket}", ticket);

            var tgsKey = _keyManager.Keys["tgs"];
            var encryptedTicket = Des.Encrypt(tgsKey, ticket);
            Log.Information("Step #2.3. Encrypt the ticket using [AuthServer <-> TGS] key: {Key}", Encoding.UTF8.GetString(tgsKey));

            var authMessage = new AuthResponse
            {
                EncryptedTicket = encryptedTicket,
                Key = sessionKey
            };
            Log.Information("Step #2.4. Build an authentication response message: {@AuthResponse}", authMessage);

            var encryptedMessage = Des.Encrypt(_keyManager.Keys[login], authMessage);
            Log.Information("Step #2.5. Encrypt the message using [{Login} <-> AuthServer] key before sending response", login);

            return Ok(Convert.ToBase64String(encryptedMessage));
        }
    }
}
