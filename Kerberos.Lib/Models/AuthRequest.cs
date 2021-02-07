namespace Kerberos.Lib.Models
{
    public class AuthRequest
    {
        public byte[] EncryptedTicket { get; set; }
        public byte[] EncryptedAuthBlock { get; set; }
        public string Recepient { get; set; }
    }
}
