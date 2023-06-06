using EncryptionService.Interface;
using EncryptionService.Model;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;

namespace EncryptionService
{
    public class BouncyCastleForLargeFileService : IBouncyCastleForLargeFileService
    {
        private const string RsaAlgorithm = "RSA/ECB/PKCS1Padding";
        private const string AesAlgorithm = "AES/CBC/PKCS7Padding";
        private const string SignatureAlgorithm = "SHA256WITHRSA";

        private readonly AsymmetricCipherKeyPair _serverKeyPair;
        private readonly AsymmetricCipherKeyPair _clientKeyPair;

        public BouncyCastleForLargeFileService()
        {
            _serverKeyPair = GenerateRSAKeyPair();
            _clientKeyPair = GenerateRSAKeyPair();
        }

        public async Task<string> TestEncryption()
        {
            var fileContent = "";
            var filePath = "dataToTest.txt";
            using (var reader = new StreamReader(filePath))
            {
                fileContent = await reader.ReadToEndAsync();
            }

            var encryptedData = EncryptAndSign(fileContent, _clientKeyPair.Public, _serverKeyPair.Private);
            var finalData = VerifyAndDecrypt(encryptedData, _serverKeyPair.Public, _clientKeyPair.Private);
            return finalData;
        }

        public byte[] Encrypt(string data, AsymmetricKeyParameter clientPublicKey)
        {
            var byteData = Encoding.UTF8.GetBytes(data);

            var aesKey = GenerateAESKey();
            var ivKey = GenerateIV();

            var encryptedData = EncryptWithAES(byteData, aesKey, ivKey);
            var encryptedAesKey = EncryptWithRSA(aesKey.GetKey(), clientPublicKey);
            var encryptedIV = EncryptWithRSA(ivKey, clientPublicKey);

            var container = new HybridEncryptedDataContainer
            {
                EncryptedData = encryptedData,
                EncryptedAesKey = encryptedAesKey,
                EncryptedIV = encryptedIV
            };

            var serializedContainer = Serialize(container);

            return serializedContainer;
        }

        public byte[] Sign(byte[] serializedContainer, AsymmetricKeyParameter serverPrivateKey)
        {
            var signature = GenerateSignature(serializedContainer, serverPrivateKey);
            var signedContainer = new SignedDataContainer
            {
                SerializedContainer = serializedContainer,
                Signature = signature
            };
            var serializedSignedContainer = Serialize(signedContainer);

            return serializedSignedContainer;
        }

        public byte[] EncryptAndSign(string data, AsymmetricKeyParameter clientPublicKey, AsymmetricKeyParameter serverPrivateKey)
        {
            var encryptedData = Encrypt(data, clientPublicKey);
            var serializedSignedContainer = Sign(encryptedData, serverPrivateKey);
            return serializedSignedContainer;
        }

        public bool Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey)
        {
            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(false, publicKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        public string Decrypt(SignedDataContainer signedContainer, AsymmetricKeyParameter clientPrivateKey)
        {
            var container = Deserialize<HybridEncryptedDataContainer>(signedContainer.SerializedContainer);

            var aseKey = DecryptWithRSA(container.EncryptedAesKey, clientPrivateKey);
            var ivKey = DecryptWithRSA(container.EncryptedIV, clientPrivateKey);

            var decryptedData = DecryptWithAES(container.EncryptedData, new KeyParameter(aseKey), ivKey);
            var decryptedString = Encoding.UTF8.GetString(decryptedData);

            return decryptedString;

        }

        public string VerifyAndDecrypt(byte[] encryptedData, AsymmetricKeyParameter serverPublicKey, AsymmetricKeyParameter clientPrivateKey)
        {
            var signedContainer = Deserialize<SignedDataContainer>(encryptedData);
            bool isVerified = Verify(signedContainer.SerializedContainer, signedContainer.Signature, serverPublicKey);

            if (!isVerified)
            {
                return "data signature verification failed";
            }

            var decryptedString = Decrypt(signedContainer, clientPrivateKey);

            return decryptedString;
        }

        #region Hepler Methods

        private T Deserialize<T>(byte[] data)
        {
            var stringData = Encoding.UTF8.GetString(data);
            var deserializeObject = JsonConvert.DeserializeObject<T>(stringData);
            return deserializeObject;
        }

        private byte[] Serialize<T>(T data)
        {
            var serializeData = JsonConvert.SerializeObject(data);
            var serializeByteData = Encoding.UTF8.GetBytes(serializeData);
            return serializeByteData;
        }

        private AsymmetricCipherKeyPair GenerateRSAKeyPair()
        {
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();

            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            return rsaKeyPairGenerator.GenerateKeyPair();
        }

        private KeyParameter GenerateAESKey()
        {
            var random = new SecureRandom();
            var keyBytes = new byte[32];
            random.NextBytes(keyBytes);
            return new KeyParameter(keyBytes);
        }

        private byte[] GenerateIV()
        {
            var random = new SecureRandom();
            var iv = new byte[16];
            random.NextBytes(iv);
            return iv;
        }

        private byte[] EncryptWithAES(byte[] data, KeyParameter aesKey, byte[] ivKey)
        {
            var cipher = CipherUtilities.GetCipher(AesAlgorithm);
            cipher.Init(true, new ParametersWithIV(aesKey, ivKey));
            return cipher.DoFinal(data);
        }

        private byte[] DecryptWithAES(byte[] encryptedData, KeyParameter aesKey, byte[] ivKey)
        {
            var cipher = CipherUtilities.GetCipher(AesAlgorithm);
            cipher.Init(false, new ParametersWithIV(aesKey, ivKey));
            return cipher.DoFinal(encryptedData);
        }

        private byte[] EncryptWithRSA(byte[] data, AsymmetricKeyParameter publicKey)
        {

            //var cipher = new Pkcs1Encoding(new RsaEngine());
            //cipher.Init(true, publicKey);
            //var rsaEncryptedData = cipher.ProcessBlock(data, 0, data.Length);

            var cipher = CipherUtilities.GetCipher(RsaAlgorithm);
            cipher.Init(true, publicKey);
            var rsaEncryptedData = cipher.DoFinal(data);

            return rsaEncryptedData;
        }

        private byte[] DecryptWithRSA(byte[] encryptedData, AsymmetricKeyParameter privateKey)
        {
            //var cipher = new Pkcs1Encoding(new RsaEngine());
            //cipher.Init(false, privateKey);
            //var decryptedData = cipher.ProcessBlock(encryptedData, 0, encryptedData.Length);

            var cipher = CipherUtilities.GetCipher(RsaAlgorithm);
            cipher.Init(false, privateKey);

            byte[] decryptedData = cipher.DoFinal(encryptedData);

            return decryptedData;
        }

        private byte[] GenerateSignature(byte[] data, AsymmetricKeyParameter privateKey)
        {
            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(true, privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        #endregion
    }
}
