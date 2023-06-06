using Org.BouncyCastle.Crypto;

namespace EncryptionService.Interface
{
    public interface IBouncyCastleService : IBaseEncyrptionService
    {
        public Task<string> TestEncryption();
    }
}
