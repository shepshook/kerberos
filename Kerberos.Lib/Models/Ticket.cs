namespace Kerberos.Lib.Models
{
    public class Ticket
    {
        public string From { get; set; }
        public string To { get; set; }
        public byte[] Key { get; set; }
        public long Timestamp { get; set; }
        public long Expiration { get; set; }
    }
}
