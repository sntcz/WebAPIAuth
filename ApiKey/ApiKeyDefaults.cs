using Microsoft.AspNetCore.Authentication;

namespace WebAPIAuth.ApiKey
{
    // https://matteosonoio.it/aspnet-core-authentication-schemes/
    public static class ApiKeyDefaults
    {
        public const string AuthenticationScheme = "ApiKey";
        public const string HeaderName = "X-API-KEY";
    }
}
