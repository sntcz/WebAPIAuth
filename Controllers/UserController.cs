using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebAPIAuth.Models;

namespace WebAPIAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> logger;
        private readonly IConfiguration config;

        public UserController(ILogger<UserController> logger, IConfiguration config)
        {
            this.logger = logger;
            this.config = config;
        }

        [Authorize(AuthenticationSchemes = NegotiateDefaults.AuthenticationScheme)]
        [Route("GetToken")]
        [HttpGet]
        public IActionResult GetToken()
        {
            var name = HttpContext.User.Identity?.Name;
            var authType = HttpContext.User.Identity?.AuthenticationType;
            logger.LogInformation($"GetToken Name: {name}, auth type: {authType}");
            if (String.IsNullOrEmpty(name))
                return Unauthorized("No negotiate (NTLM)");
            int id = 1; // Tady načíst UserID
            string token = GenerateToken(name, id);
            return Ok(token);
        }

        [HttpPost]
        [Route("Login")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [AllowAnonymous]
        public IActionResult Login(LoginUser user)
        {
            logger.LogInformation($"Login: {user.UserName}");
            if (user.Password == "123" || user.Password == String.Empty)
            {
                int id = 5; // Tady načíst UserID podle user name
                string token = GenerateToken(user.UserName, id);
                return Ok(token);
            }
            return Unauthorized("Invalid password");
        }

        [HttpGet]
        [Route("GetCurrentUser")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult GetCurrentUser()
        {
            // Vytáhnu si dříve uložené NameIdentifier z HttpContext.User
            var name = HttpContext.User.Identity?.Name;
            var nameIdentifier = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var authType = HttpContext.User.Identity?.AuthenticationType;

            return Ok($"Name: {name}, ID: {nameIdentifier}, auth type: {authType}");
        }

        // To generate JWT token
        private string GenerateToken(string user, int userId)
        {
            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,userId.ToString()),
                new Claim(ClaimTypes.Name,user),
                new Claim(ClaimTypes.Role,user)
            };
            var token = new JwtSecurityToken(config["Jwt:Issuer"],
                config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(150),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
