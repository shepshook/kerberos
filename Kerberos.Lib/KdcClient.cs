using Kerberos.Lib.Models;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Kerberos.Lib
{
    public class KdcClient
    {
        private readonly HttpClient _httpClient = new HttpClient();
        public async Task Register(string login, string password)
        {
            await _httpClient.PostAsync("http://kdc/register", 
                new FormUrlEncodedContent(new Dictionary<string, string> { { "login", login }, { "password", password } }));
        }

        public async Task<byte[]> Authenticate(string login)
        {
            var response = await _httpClient.PostAsync("http://kdc/auth", 
                new FormUrlEncodedContent(new Dictionary<string, string> { { "login", login } }));

            return Convert.FromBase64String(await response.Content.ReadAsStringAsync());
        }

        public async Task<byte[]> RequestTicket(AuthRequest request)
        {
            var response = await _httpClient.PostAsync("http://kdc/tgs",
                new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json"));

            return Convert.FromBase64String(await response.Content.ReadAsStringAsync());
        }

        public async Task<byte[]> AuthOnServer(AuthRequest request) 
        {
            var response = await _httpClient.PostAsync($"http://{request.Recepient}/auth",
                new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json"));

            return Convert.FromBase64String(await response.Content.ReadAsStringAsync());
        }
    }
}
