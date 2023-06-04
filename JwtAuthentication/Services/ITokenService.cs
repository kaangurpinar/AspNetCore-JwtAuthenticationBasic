using JwtAuthentication.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JwtAuthentication.Services
{
    public interface ITokenService
    {
        string GenerateAccessToken(AppUser user);

        string GenerateRefreshToken();

        ClaimsPrincipal GetPrincipalFromExpiredToken(string expiredToken);
        /*
        string CreateToken(AppUser appUser);

        JwtSecurityToken CreateJwtToken(List<Claim> claims, SigningCredentials signingCredentials, DateTime expiration);

        List<Claim> CreateClaims(AppUser appUser);

        SigningCredentials CreateSigningCredentials();
        */
    }
}
