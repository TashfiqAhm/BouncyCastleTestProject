using EncryptionService.Interface;
using EncryptionService.Model;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using System.Text;
using Newtonsoft.Json;

namespace EncryptionService
{
    public class BouncyCastleService : IBouncyCastleService
    {
        private const string Algorithm = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";
        private const string SignatureAlgorithm = "SHA512WITHRSA";
        private const string SignData = "data to sign with";

        private readonly AsymmetricCipherKeyPair _serverKeyPair;
        private readonly AsymmetricCipherKeyPair _clientKeyPair;

        public BouncyCastleService()
        {
            _serverKeyPair = GenerateKeyPair();
            _clientKeyPair = GenerateKeyPair();
        }


        public string TestEncryption(string mainData, string signData)
        {
            /*var keyPair = GenerateKeyPair();
            var publicKey = keyPair.Public;
            var privateKey = keyPair.Private;

            var encryptedData = Encrypt(mainData, publicKey);
            var decryptedData = Decrypt(encryptedData, privateKey);

            var signed = Sign(signData, privateKey);
            var verifyResult = Verify(signData, publicKey, signed);

            var returnString = verifyResult ? decryptedData : "not valid";
            return returnString;*/

            var encryptedDataModelString = EncryptAndSign(mainData);
            var decryptedData = DecryptAndVerify(encryptedDataModelString);

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

            byte[] decryptedData = cipher.DoFinal(encryptedData);
            var initialData = Encoding.UTF8.GetString(decryptedData);

            return initialData;
        }

        public byte[] Sign(string data, AsymmetricKeyParameter privateKey)
        {
            var byteData = Encoding.UTF8.GetBytes(data);
            //var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(true, privateKey);
            signer.BlockUpdate(byteData, 0, byteData.Length);
            var sigBnData = signer.GenerateSignature();
            return sigBnData;
        }

        public bool Verify(string data, AsymmetricKeyParameter publicKey, byte[]? signature)
        {
            if (signature == null)
                return false;

            var byteData = Encoding.UTF8.GetBytes(data);
            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(false, publicKey);
            signer.BlockUpdate(byteData, 0, byteData.Length);
            return signer.VerifySignature(signature);
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            return rsaKeyPairGenerator.GenerateKeyPair();
        }

        private string EncryptAndSign(string data)
        {
            var encryptedData = new EncryptedDataModel()
            {
                EncryptedData = Encrypt(data, _clientKeyPair.Public),
                Signature = Sign(SignData, _serverKeyPair.Private)
            };

            var encryptedDataModelString = JsonConvert.SerializeObject(encryptedData);

            return encryptedDataModelString;

        }

        private string DecryptAndVerify(string encryptedDataModelString)
        {
            var encryptedDataModel = JsonConvert.DeserializeObject<EncryptedDataModel>(encryptedDataModelString);

            var signatureVerify = Verify(SignData, _serverKeyPair.Public, encryptedDataModel?.Signature);

            var decryptedMessage =
                signatureVerify ? Decrypt(encryptedDataModel?.EncryptedData, _clientKeyPair.Private) : "";

            return decryptedMessage;
        }

    }
}


// sign with client public key for encryption
// so client can decrypt with own private key
// sign with own server private key
// so client can verify with server public key
