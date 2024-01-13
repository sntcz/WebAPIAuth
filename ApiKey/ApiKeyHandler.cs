using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace WebAPIAuth.ApiKey
{
    public class ApiKeyHandler : AuthenticationHandler<ApiKeyOptions>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ApiKeyHandler"/>.
        /// </summary>
        /// <param name="options">The monitor for the options instance.</param>
        /// <param name="logger">The <see cref="ILoggerFactory"/>.</param>
        /// <param name="encoder">The <see cref="UrlEncoder"/>.</param>
        /// <param name="clock">The <see cref="ISystemClock"/>.</param>
#if NET8_0_OR_GREATER
        public ApiKeyInHeaderHandler(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        { /* NOP */ }

        [Obsolete("ISystemClock is obsolete, use TimeProvider on AuthenticationSchemeOptions instead.")]
#endif
        public ApiKeyHandler(IOptionsMonitor<ApiKeyOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        { /* NOP */ }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var apiKey = Context.Request.Headers[Options.HeaderName];
            // If no authorization header found, nothing to process further
            if (string.IsNullOrEmpty(apiKey))
            {
                return AuthenticateResult.NoResult();
            }
            var claims = await Options.OnValidateKey(apiKey);
            if (claims == null)
            {
                return AuthenticateResult.Fail(Options.FailMessage);
            }
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
    }
}
