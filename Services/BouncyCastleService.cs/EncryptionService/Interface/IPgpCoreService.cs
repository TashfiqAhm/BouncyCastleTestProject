using Org.BouncyCastle.Crypto;

namespace EncryptionService.Interface
{
    public interface IPgpCoreService : IBaseEncyrptionService 
    {
        public Task<string> TestEncryption(string mainData, string signData);
        /*public byte[] Encrypt(string data, AsymmetricKeyParameter publicKey);
        public string Decrypt(byte[] encryptedData, AsymmetricKeyParameter privateKey);
        public byte[] Sign(string data, AsymmetricKeyParameter privateKey);
        public bool Verify(string data, AsymmetricKeyParameter publicKey, byte[] sign);*/
    }
}
