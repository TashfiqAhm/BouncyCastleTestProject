using EncryptionService.Interface;
using EncryptionService.Model;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Ocsp;

namespace EncryptionService
{
    public class BouncyCastleService : IBouncyCastleService
    {
        //private const string Algorithm = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";
        private const string Algorithm = "RSA/ECB/PKCS1Padding";
        private const string SignatureAlgorithm = "SHA256WITHRSA";

        private readonly AsymmetricCipherKeyPair _serverKeyPair;
        private readonly AsymmetricCipherKeyPair _clientKeyPair;

        public BouncyCastleService()
        {
            _serverKeyPair = GenerateKeyPair();
            _clientKeyPair = GenerateKeyPair();
        }

        public async Task<string> TestEncryption()
        {
            var fileContent = "";
            var filePath = "dataToTest.txt";
            using (var reader = new StreamReader(filePath))
            {
                fileContent = await reader.ReadToEndAsync();
            }

            // this method do not support large data
            // large data string length >= 10^7
            fileContent = "demo data";

            var encryptedData = EncryptAndSign(fileContent, _clientKeyPair.Public, _serverKeyPair.Private);
            var decryptedData = DecryptAndVerify(encryptedData, _serverKeyPair.Public, _clientKeyPair.Private);

            return decryptedData;
        }

        public byte[] Encrypt(string data, AsymmetricKeyParameter publicKey)
        {
            var byteData = Encoding.UTF8.GetBytes(data);
            var cipher = CipherUtilities.GetCipher(Algorithm);
            cipher.Init(true, publicKey);
            var encryptedData = cipher.DoFinal(byteData);

            return encryptedData;
        }

        public string Decrypt(byte[]? encryptedData, AsymmetricKeyParameter privateKey)
        {
            if (encryptedData == null)
                return "no data found";

            var cipher = CipherUtilities.GetCipher(Algorithm);
            cipher.Init(false, privateKey);

            var decryptedData = cipher.DoFinal(encryptedData);
            var initialData = Encoding.UTF8.GetString(decryptedData);

            return initialData;
        }

        public byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey)
        {
            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(true, privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            var sigBnData = signer.GenerateSignature();

            return sigBnData;
        }

        public bool Verify(byte[] data, AsymmetricKeyParameter publicKey, byte[]? signature)
        {
            if (signature == null)
                return false;
            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(false, publicKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();

            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            return rsaKeyPairGenerator.GenerateKeyPair();
        }

        private byte[] EncryptAndSign(string data, AsymmetricKeyParameter clientPublicKey, AsymmetricKeyParameter serverPrivateKey)
        {
            var encryptedData = Encrypt(data, clientPublicKey);
            var signature = Sign(encryptedData, serverPrivateKey);

            var encryptedDataModel = new EncryptedDataModel()
            {
                EncryptedData = encryptedData,
                Signature = signature
            };

            var encryptedDataModelString = JsonConvert.SerializeObject(encryptedDataModel);
            var encryptedDataModelSbBytes = Encoding.UTF8.GetBytes(encryptedDataModelString);

            return encryptedDataModelSbBytes;
        }

        private string DecryptAndVerify(byte[] encryptedData, AsymmetricKeyParameter serverPublicKey, AsymmetricKeyParameter clientPrivateKey )
        {
            var encryptedStringData = Encoding.UTF8.GetString(encryptedData);
            var encryptedDataModel = JsonConvert.DeserializeObject<EncryptedDataModel>(encryptedStringData);

            var signatureVerify = Verify(encryptedDataModel.EncryptedData, serverPublicKey, encryptedDataModel?.Signature);

            var decryptedMessage =
                signatureVerify ? Decrypt(encryptedDataModel?.EncryptedData, _clientKeyPair.Private) : "";

            return decryptedMessage;
        }

    }
}
