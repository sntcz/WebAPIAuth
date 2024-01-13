namespace WebAPIAuth.Models
{
    public class UserInformation
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public string? AuthenticationType { get; set; }
        public string[]? Roles { get; set; }
    }
}
