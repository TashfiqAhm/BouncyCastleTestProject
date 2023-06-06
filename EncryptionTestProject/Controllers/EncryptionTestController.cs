using EncryptionService.Interface;
using Microsoft.AspNetCore.Mvc;

namespace EncryptionTestProject.Controllers
{
    [Route("api")]
    public class EncryptionTestController : ControllerBase
    {
        private readonly IBouncyCastleService _bouncyCastleService;
        private readonly IBouncyCastleForLargeFileService _bouncyCastleForLargeFileService;
        private readonly IPgpCoreService _pgpCoreService;

        public EncryptionTestController(IBouncyCastleService bouncyCastleService, 
            IPgpCoreService pgpCoreService,
            IBouncyCastleForLargeFileService bouncyCastleForLargeFileService)
        {
            _bouncyCastleService = bouncyCastleService;
            _bouncyCastleForLargeFileService = bouncyCastleForLargeFileService;
            _pgpCoreService = pgpCoreService;
        }

        [HttpGet("EncryptionTest")]
        public async Task<ActionResult<string>> testEncryption()
        {
            //var lastData = await _bouncyCastleForLargeFileService.TestEncryption();
            var lastData = await _bouncyCastleService.TestEncryption();
            //var lastData = await _pgpCoreService.TestEncryption();
            return Ok(lastData);
        }
    }
}
