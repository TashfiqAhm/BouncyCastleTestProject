namespace EncryptionService.Interface
{
    public interface IBouncyCastleForLargeFileService : IBaseEncyrptionService
    {
        public Task<string> TestEncryption();
    }
}
