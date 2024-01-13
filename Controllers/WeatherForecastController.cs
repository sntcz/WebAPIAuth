using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAPIAuth.ApiKey;
using WebAPIAuth.Models;

namespace WebAPIAuth.Controllers
{
    /// <summary>
    /// Wetaher forecast controller
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    [Authorize(AuthenticationSchemes = $"{NegotiateDefaults.AuthenticationScheme},{JwtBearerDefaults.AuthenticationScheme},{ApiKeyDefaults.AuthenticationScheme}")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Can be used for any authorized user (NTLM, JWT Bearer or API key)
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<WeatherForecast>), StatusCodes.Status200OK)]
        public IEnumerable<WeatherForecast> Get()
        {
            // Load NameIdentifier from HttpContext.User
            var name = HttpContext.User.Identity?.Name;
            var nameIdentifier = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var authType = HttpContext.User.Identity?.AuthenticationType;

            _logger.LogInformation($"Get Weather by Name: {name}, ID: {nameIdentifier}, auth type: {authType}");

            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Today.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}