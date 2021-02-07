using System.Collections.Generic;
using System;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace Kerberos.Lib
{
    public class KeyManager
    {
        public Dictionary<string, byte[]> Keys { get; } = new Dictionary<string, byte[]>();

        public static byte[] GenerateSessionKey(string source = null)
        {
            byte[] bytes;
            if (source != null)
                bytes = Encoding.Default.GetBytes(source);
            else
                bytes = Guid.NewGuid().ToByteArray();

            var hash = SHA256.Create().ComputeHash(bytes).Take(7).ToArray();
            return hash;
        }
    }
}
