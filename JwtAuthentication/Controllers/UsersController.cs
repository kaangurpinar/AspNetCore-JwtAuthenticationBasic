using AspNetCore.Identity.MongoDbCore.Models;
using JwtAuthentication.Models;
using JwtAuthentication.Services;
using JwtAuthentication.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;

        private readonly ITokenService _tokenService;

        public UsersController(UserManager<AppUser> userManager, ITokenService tokenService)
        {
            _userManager = userManager;
            _tokenService = tokenService;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(UserViewModel userViewModel)
        {
            if(ModelState.IsValid)
            {
                var user = new AppUser()
                {
                    UserName = userViewModel.UserName,
                    Email = userViewModel.Email
                };

                var result = await _userManager.CreateAsync(user, userViewModel.Password);

                if (result.Succeeded)
                {
                    return Ok();
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                }
            }
            return BadRequest(ModelState);
        }

        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<AuthResponse>> Login(AuthRequest authRequest)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(authRequest.UserName);

                if (user == null)
                {
                    return BadRequest();
                }

                var passwordIsValid = await _userManager.CheckPasswordAsync(user, authRequest.Password);

                if (!passwordIsValid)
                {
                    return BadRequest();
                }

                var accessToken = _tokenService.GenerateAccessToken(user);

                var refreshToken = _tokenService.GenerateRefreshToken();

                /*
                Token token = new Token() { Name = "AccessToken", Value = accessToken };

                user.Tokens.Add(token);
                */

                user.AccessToken = accessToken;
                user.RefreshToken = refreshToken;

                await _userManager.UpdateAsync(user);
                

                return Ok(new AuthResponse()
                {
                    UserName = user.UserName,
                    Email = user.Email,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                });
            }
            return BadRequest(ModelState);
        }

        [HttpPost]
        [Route("refresh")]
        public async Task<ActionResult<TokenViewModel>> Refresh(TokenViewModel tokenViewModel)
        {
            if (ModelState.IsValid)
            {
                string accessToken = tokenViewModel.AccessToken;
                string refreshToken = tokenViewModel.RefreshToken;

                var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);

                var name = principal.Identity.Name;

                var user = await _userManager.FindByNameAsync(name);

                if(user == null)
                {
                    return BadRequest();
                }

                var newAccessToken = _tokenService.GenerateAccessToken(user);
                var newRefreshToken = _tokenService.GenerateRefreshToken();

                user.AccessToken = newAccessToken;
                user.RefreshToken = newRefreshToken;

                await _userManager.UpdateAsync(user);

                return Ok(new TokenViewModel()
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken,
                });
            }

            return BadRequest(ModelState);
        }

        /*
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<AuthResponse>> Login(AuthRequest authRequest)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(authRequest.UserName);

                if (user == null)
                {
                    return BadRequest();
                }

                var passwordIsValid = await _userManager.CheckPasswordAsync(user, authRequest.Password);

                if (!passwordIsValid)
                {
                    return BadRequest();
                }

                var accessToken = _tokenService.CreateToken(user);

                Token token = new Token() { Name = "AccessToken", Value = accessToken }; 

                user.Tokens.Add(token);

                await _userManager.UpdateAsync(user);

                return Ok(new AuthResponse()
                {
                    UserName = user.UserName,
                    Email = user.Email,
                    Token = accessToken
                });
            }
            return BadRequest(ModelState);
        }
        */
    }
}
