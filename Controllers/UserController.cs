using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
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

        [HttpGet]
        [Route("Login")]
        [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        [Authorize(AuthenticationSchemes = NegotiateDefaults.AuthenticationScheme)]
        public IActionResult Login()
        {
            try
            {
                var name = HttpContext.User.Identity?.Name;
                var authType = HttpContext.User.Identity?.AuthenticationType;
                logger.LogInformation($"GetToken Name: {name}, auth type: {authType}");
                if (String.IsNullOrEmpty(name))
                    return Unauthorized(new ProblemDetails() { Title = "No negotiate (NTLM)" });
                // Load UserID from name
                int id = 1; // Magic number !!!
                string token = GenerateToken(name, id, "Role", "Magician", "Human");
                return Ok(new LoginResponse() { Token = token });
            }
            catch (Exception ex)
            {
                return Problem(ex.Message);
            }
        }

        [HttpPost]
        [Route("Login")]
        [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        [AllowAnonymous]
        public IActionResult Login(LoginUser user)
        {
            try
            {
                if (user.UserName == null)
                {
                    // Do not throw exception withou try/catch
                    throw new Exception("Invalid input, null user structure.");
                }

                logger.LogInformation($"Login: {user.UserName}");
                // Load UserID from user name and check the password
                if (user.Password == "123" || user.Password == String.Empty)
                {
                    int id = 5; // Magic number !!!
                    string token = GenerateToken(user.UserName, id, user.UserName.StartsWith("a") ? "Administrator" : "User", "Dwarf");
                    return Ok(new LoginResponse() { Token = token });
                }
                return Unauthorized(new ProblemDetails() { Title = "Invalid user name or password" });
            }
            catch (Exception ex)
            {
                return Problem(ex.Message);
            }
        }

        [HttpGet]
        [Route("GetCurrentUser")]
        [ProducesResponseType(typeof(UserInformation), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public IActionResult GetCurrentUser()
        {
            try
            {
                // Vytáhnu si dříve uložené NameIdentifier z HttpContext.User
                var name = HttpContext.User.Identity?.Name;
                Int32.TryParse(HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var nameIdentifier);
                var authType = HttpContext.User.Identity?.AuthenticationType;
                var roles = HttpContext.User.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToArray();
                var user = new UserInformation()
                {
                    Id = nameIdentifier,
                    Name = name,
                    AuthenticationType = authType,
                    Roles = roles
                };
                return Ok(user);
            }
            catch (Exception ex)
            {
                return Problem(ex.Message);
            }

        }

        // To generate JWT token
        private string GenerateToken(string user, int userId, params string[] roles)
        {
            List<Claim> claims = new List<Claim>(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier,userId.ToString()),
                    new Claim(ClaimTypes.Name,user),
                });
            foreach (string role in roles)
            {

                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            if (!Int32.TryParse(config["Jwt:Expire"], out int expireMinutes))
            {
                expireMinutes = 150;
            }
            var token = new JwtSecurityToken(config["Jwt:Issuer"],
                config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(expireMinutes),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
