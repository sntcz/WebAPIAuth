using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace WebAPIAuth.ApiKey
{
    public static class ApiKeyExtensions
    {

        /// <summary>
        /// Enables API key authentication using the specified scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder)
            => builder.AddApiKey(ApiKeyDefaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Enables API key authentication using the specified scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="configureOptions">A delegate that allows configuring <see cref="JwtBearerOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder,
            Action<ApiKeyOptions> configureOptions)
            => builder.AddApiKey(ApiKeyDefaults.AuthenticationScheme, configureOptions);


        /// <summary>
        /// Enables API key authentication using the specified scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">A delegate that allows configuring <see cref="JwtBearerOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder, string authenticationScheme,
            Action<ApiKeyOptions> configureOptions)
            => builder.AddApiKey(authenticationScheme, displayName: null, configureOptions: configureOptions);

        /// <summary>
        /// Enables API key authentication using the specified scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name for the authentication handler.</param>
        /// <param name="configureOptions">A delegate that allows configuring <see cref="JwtBearerOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder, string authenticationScheme,
            string? displayName, Action<ApiKeyOptions> configureOptions)
        {
            return builder.AddScheme<ApiKeyOptions, ApiKeyHandler>(authenticationScheme, displayName, configureOptions);
        }

    }
}
