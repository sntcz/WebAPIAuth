using System.ComponentModel.DataAnnotations;

namespace WebAPIAuth.Models
{
    /// <summary>
    /// User login name and password
    /// </summary>
    public class LoginUser
    {
        /// <summary>
        /// User name
        /// </summary>
        /// <example>admin</example>
        [Required]
        public string? UserName { get; set; }
        /// <summary>
        /// Password
        /// </summary>
        /// <example>P@ssw0rd</example>
        public string? Password { get; set; }
    }
}
