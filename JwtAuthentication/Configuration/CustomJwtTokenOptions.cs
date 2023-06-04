namespace JwtAuthentication.Configuration
{
    public class CustomJwtTokenOptions
    {
        public string ValidIssuer { get; set; }

        public string ValidAudience { get; set; }

        public string SymmetricSecurityKey { get; set; }
    }
}
