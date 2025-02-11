using System.Net.Http.Json;
using Bcx.Login.Cli.Consts;
using Bcx.Login.Cli.OAuth;

namespace Bcx.Login.Cli.Handlers
{
    public static class LoginWithSecret
    {
        public async static Task HandleAsync(
            string clientIdArg,
            string? secretKeyOpt = null
        )
        {
            Console.WriteLine("Generating bearer token with client_id + secret key");

            if (string.IsNullOrWhiteSpace(secretKeyOpt))
                throw new IOException("Unable to resolve secretKeyOpt");

            var clientToken = new HttpClient();

            var requestToken = new HttpRequestMessage
            {
                RequestUri = new Uri(BecomexConsts.TokenUrl),
                Method = HttpMethod.Post,
                Content = new FormUrlEncodedContent(new List<KeyValuePair<string, string>>()
                {
                    new("client_id", clientIdArg),
                    new("grant_type", "client_credentials"),
                    new("scope", "openid"),
                    new("client_secret", secretKeyOpt)
                })
            };

            var responseToken = await clientToken.SendAsync(requestToken);

            if (!responseToken.IsSuccessStatusCode)
            {
                Console.WriteLine("Fail");
                return;
            }

            var responseMap = await responseToken.Content.ReadFromJsonAsync<OAuthTokenResponse>(OAuthConsts.OAuthJsonResponseOptions);

            if (responseMap is null) 
            {
                Console.WriteLine("Unable to deserialize response body.");
                return;
            }

            Console.WriteLine($"Bearer: {responseMap.AccessToken}");
        }
    }
}