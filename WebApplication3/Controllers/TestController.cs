using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace WebApplication3.Controllers {

    [ApiController]
    public class TestController : ControllerBase {
        [Authorize, HttpGet("claims")]
        public IActionResult Claims() {
            return Ok(User.Claims.ToDictionary(c => c.Type, c => c.Value));
        }

        [AllowAnonymous, HttpGet("token")]
        public IActionResult Token() {
            var handler = new JwtSecurityTokenHandler();
            var key = Convert.FromBase64String("Jnl8XjBKeScpYzdHXWw/MytEQytNS3BLK25hOzNhWWM=");

            var descriptor = new SecurityTokenDescriptor {
                Subject = new ClaimsIdentity(
                    new Claim[] {
                        new Claim("group", "test")
                    }, JwtBearerDefaults.AuthenticationScheme),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = handler.CreateToken(descriptor);
            var jwt = handler.WriteToken(token);
            return Ok(new { token = jwt });
        }


    }
}
