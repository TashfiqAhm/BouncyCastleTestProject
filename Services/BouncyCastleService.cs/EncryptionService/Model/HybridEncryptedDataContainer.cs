namespace EncryptionService.Model
{
    public class HybridEncryptedDataContainer
    {
        public byte[] EncryptedData { get; set; }
        public byte[] EncryptedAesKey { get; set; }
        public byte[] EncryptedIV { get; set; }
    }
}
