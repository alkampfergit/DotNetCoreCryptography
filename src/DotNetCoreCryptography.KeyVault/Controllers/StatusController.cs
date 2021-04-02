using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace DotNetCoreCryptography.KeyVault.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class StatusController : ControllerBase
    {
        private readonly ILogger<StatusController> _logger;

        public StatusController(ILogger<StatusController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("get")]
        public object Get()
        {
            _logger.LogDebug("Status Controller Get From user {userName} with auth type {authType}", HttpContext.User.Identity.Name, HttpContext.User.Identity.AuthenticationType);
            return new
            {
                Status = "OK",
                User = HttpContext.User.Identity.Name,
            };
        }
    }
}
