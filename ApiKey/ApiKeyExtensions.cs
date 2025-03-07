using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace WebAPIAuth.ApiKey
{
    /// <summary>
    /// API Key Authentication extensions for builder
    /// </summary>
    /// <remarks>
    /// See also <seealso href="https://matteosonoio.it/aspnet-core-authentication-schemes/"/>
    /// </remarks>
    /// <example>
    /// builder.Services.AddAuthentication(ApiKeyDefaults.AuthenticationScheme)
    ///     .AddApiKey(options =>
    ///     {
    ///         options.ApiKey = builder.Configuration["ApiKey:Key"];
    ///         options.OwnerName = builder.Configuration["ApiKey:Owner"];
    ///         string roles = builder.Configuration["ApiKey:Roles"];
    ///         if (roles != null)
    ///         {
    ///             options.Roles = roles.Split(new char[] { ',', ';' },
    ///                 StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    ///         }
    ///     });
    /// </example>
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
        /// <param name="configureOptions">A delegate that allows configuring <see cref="ApiKeyOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder,
            Action<ApiKeyOptions> configureOptions)
            => builder.AddApiKey(ApiKeyDefaults.AuthenticationScheme, configureOptions);


        /// <summary>
        /// Enables API key authentication using the specified scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">A delegate that allows configuring <see cref="ApiKeyOptions"/>.</param>
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
        /// <param name="configureOptions">A delegate that allows configuring <see cref="ApiKeyOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder, string authenticationScheme,
            string? displayName, Action<ApiKeyOptions> configureOptions)
        {
            return builder.AddScheme<ApiKeyOptions, ApiKeyHandler>(authenticationScheme, displayName, configureOptions);
        }

    }
}
