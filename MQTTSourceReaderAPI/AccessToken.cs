using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AccessToken
{
    public class AccessToken
    {
        private readonly ILogger<AccessToken> _logger;

        /// <summary>
        /// Secret key used to sign the JWT token
        /// </summary>
        private readonly string SecretKey;

        /// <summary>
        /// Issuer of the JWT token
        /// </summary>
        private readonly string Issuer;

        /// <summary>
        /// Expiration time of the JWT token in minutes
        /// </summary>
        private readonly int ExpirationMinutes;

        public AccessToken(ILogger<AccessToken> logger)
        {
            _logger = logger;

            // Get the secret key, issuer, and expiration time from the environment variables
            SecretKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY") ?? throw new ArgumentNullException("JWT_SECRET_KEY");
            Issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new ArgumentNullException("JWT_ISSUER");
            ExpirationMinutes = int.Parse(Environment.GetEnvironmentVariable("JWT_EXPIRATION_MINUTES") ?? "5");
        }

        [Function("AccessToken")]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequest req)
        {
            // Generate a JWT token
            var token = GenerateJwtToken();

            _logger.LogInformation("C# HTTP trigger function processed a request.");
            return new OkObjectResult(token);
        }

        /// <summary>
        /// Generates a JWT token with the specified claims
        /// </summary>
        /// <returns></returns>
        private string GenerateJwtToken()
        {
            // Create the security key
            var key = Encoding.ASCII.GetBytes(SecretKey);
            // Create the token descriptor
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                new Claim(ClaimTypes.Name, "Raymond"),
                new Claim(ClaimTypes.Email, "me@example.com"),
            }),
                Expires = DateTime.UtcNow.AddMinutes(ExpirationMinutes),
                Issuer = Issuer,
                Audience = "api.example.com",
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };
            // Create the JWT token
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
