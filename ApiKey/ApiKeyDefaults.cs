using Microsoft.AspNetCore.Authentication;

namespace WebAPIAuth.ApiKey
{
    /// <summary>
    /// Default values for API Key Authentication
    /// </summary>
    /// <remarks>
    /// See also <seealso href="https://matteosonoio.it/aspnet-core-authentication-schemes/"/>
    /// </remarks>
    public static class ApiKeyDefaults
    {
        public const string AuthenticationScheme = "ApiKey";
        public const string HeaderName = "X-API-KEY";
    }
}
