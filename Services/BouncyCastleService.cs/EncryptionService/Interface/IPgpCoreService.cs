namespace EncryptionService.Interface
{
    public interface IPgpCoreService : IBaseEncyrptionService 
    {
        void Encrypt(byte[] data);
        void Decrypt(byte[] encryptedData);
    }
}
