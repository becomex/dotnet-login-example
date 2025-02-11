namespace Bcx.Login.Cli.OAuth;

public record OAuthTokenResponse(string AccessToken, string RefreshToken, long ExpiresIn, long RefreshExpiresIn, string Scope);