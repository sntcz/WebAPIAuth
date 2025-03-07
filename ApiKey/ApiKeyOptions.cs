using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Options;

namespace WebAPIAuth.ApiKey
{
    /// <summary>
    /// Simple options for API Key Authentication
    /// </summary>
    /// <remarks>
    /// See also <seealso href="https://matteosonoio.it/aspnet-core-authentication-schemes/"/>
    /// </remarks>
    public class ApiKeyOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// This is required property. It is the name of the header of the API Key.
        /// </summary>
        public string HeaderName { get; set; } = ApiKeyDefaults.HeaderName;
        /// <summary>
        /// API KEY
        /// </summary>
        public string? ApiKey { get; set; } = null;
        /// <summary>
		/// Owner of the API Key. It can be username or any other key owner name.
		/// </summary>
        public string OwnerName { get; set; } = "VALID USER";
        /// <summary>
        /// Owner ID of the API Key. It can be null, or any other string.
        /// </summary>
        public string? OwnerID { get; set; } = null;
        /// <summary>
        /// Roles asigned to the API Key.
        /// </summary>
        public IEnumerable<string>? Roles { get; set; } = null;
        /// <summary>
        /// Fail message for the invalid API Key.
        /// </summary>
        public string FailMessage { get; set; } = "Invalid API KEY";
        /// <summary>
        /// API Key validation method, return null for invalid API Key or Claim list for valid authentication
        /// </summary>
        public Func<string, Task<IEnumerable<Claim>?>> OnValidateKey { get; set; }

        public ApiKeyOptions()
        {
            OnValidateKey = (apiKey) =>
            {
                IEnumerable<Claim>? claims = null;
                if (apiKey == ApiKey)
                {
                    claims = new List<Claim>(new[] { new Claim(ClaimTypes.Name, OwnerName) });
                    if (OwnerID != null)
                        ((List<Claim>)claims).Add(new Claim(ClaimTypes.NameIdentifier, OwnerID));
                    if (Roles != null)
                    {
                        foreach (string role in Roles)
                        {
                            ((List<Claim>)claims).Add(new Claim(ClaimTypes.Role, role));
                        }
                    }
                }
                return Task.FromResult(claims);
            };
        }

    }
}
