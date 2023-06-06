using EncryptionService.Interface;
using PgpCore;

namespace EncryptionService
{
    public class PgpCoreService : IPgpCoreService
    {
        private readonly string _publicKeyPath = @"C:\Users\Tashfiq\Desktop\demoTest\PgpCorePublic.asc";
        private readonly string _privateKeyPath = @"C:\Users\Tashfiq\Desktop\demoTest\PgpCorePublic.asc";
        private readonly string _username = "random username";
        private readonly string _password = "random password";
        public PgpCoreService()
        {
            
        }
        public async Task<string> TestEncryption(string mainData, string signData)
        {
            var fileContent = "demo string";
            GenerateKey();
            /*var filePath = "dataToTest.txt";
            

            using (var reader = new StreamReader(filePath))
            {
                fileContent = await reader.ReadToEndAsync();

            }*/

            var p = fileContent.Length;

            var encryptedDataModelString = await EncryptAndSign(fileContent);
            var decryptedData = await DecryptAndVerify(encryptedDataModelString);

            return decryptedData;
        }

        public void GenerateKey()
        {
            using (PGP pgp = new PGP())
            {
                pgp.GenerateKey(_publicKeyPath, _privateKeyPath, _username, _password);
            }
        }
         
        public async Task<string> Encrypt(string data)
        {
            // Load keys
            var publicKey = await File.ReadAllTextAsync(_publicKeyPath);
            var encryptionKeys = new EncryptionKeys(publicKey);

            // Encrypt
            var pgp = new PGP(encryptionKeys);
            var encryptedContent = await pgp.EncryptArmoredStringAsync(data);
            return encryptedContent;
        }

        public async Task<string> Decrypt(string data)
        {
            // Load keys
            var privateKey = await File.ReadAllTextAsync(_privateKeyPath);
            EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, _password);

            var pgp = new PGP(encryptionKeys);

            // Decrypt
            var decryptedContent = await pgp.DecryptArmoredStringAsync(data);
            return decryptedContent;
        }

        public async Task<string> Sign(string data)
        {
            // Load keys
            var privateKey = await File.ReadAllTextAsync(_privateKeyPath);
            var encryptionKeys = new EncryptionKeys(privateKey, _password);

            var pgp = new PGP(encryptionKeys);

            // Sign
            var signedContent = await pgp.SignArmoredStringAsync(data);
            return signedContent;
        }

        public async Task<bool> Verify(string data)
        {
            // Load keys
            var publicKey = await File.ReadAllTextAsync(_publicKeyPath);
            var encryptionKeys = new EncryptionKeys(publicKey);

            var pgp = new PGP(encryptionKeys);

            // Verify
            var verified = await pgp.VerifyArmoredStringAsync(data);
            return verified;
        }

        public async Task<string> EncryptAndSign(string data)
        {
            // Load keys
            var publicKey = await File.ReadAllTextAsync(_publicKeyPath);
            var privateKey = await File.ReadAllTextAsync(_privateKeyPath);
            var encryptionKeys = new EncryptionKeys(publicKey, privateKey, _password);

            var pgp = new PGP(encryptionKeys);

            // Encrypt and Sign
            var encryptedSignedContent = await pgp.EncryptArmoredStringAndSignAsync(data);
            return encryptedSignedContent;
        }

        public async Task<string> DecryptAndVerify(string data)
        {
            // Load keys
            var publicKey = await File.ReadAllTextAsync(_publicKeyPath);
            var privateKey = await File.ReadAllTextAsync(_privateKeyPath);
            var encryptionKeys = new EncryptionKeys(publicKey, privateKey, _password);

            var pgp = new PGP(encryptionKeys);

            // Decrypt and Verify
            string content = await pgp.DecryptArmoredStringAndVerifyAsync(data);
            return content;
        }
    }
}
