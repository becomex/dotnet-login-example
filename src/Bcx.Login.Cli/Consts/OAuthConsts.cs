using System.Text.Json;

namespace Bcx.Login.Cli.Consts;

public static class OAuthConsts
{
    public static JsonSerializerOptions OAuthJsonResponseOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };
}