using EncryptionService.Interface;
using Microsoft.AspNetCore.Mvc;

namespace EncryptionTestProject.Controllers
{
    [Route("api")]
    public class EncryptionTestController : ControllerBase
    {
        private readonly IBouncyCastleService _bouncyCastleService;

        public EncryptionTestController(IBouncyCastleService bouncyCastleService)
        {
            _bouncyCastleService = bouncyCastleService;
        }

        // GET: /api/Templates/id/Shared
        [HttpGet("BouncyCastle")]
        public async Task<ActionResult<string>> testEncryption()
        {
            var mainData = "hello qwerty";
            var signData = "data to check sign";
            var lastData = _bouncyCastleService.TestEncryption(mainData, signData);
            return Ok(lastData);
        }
    }
}
