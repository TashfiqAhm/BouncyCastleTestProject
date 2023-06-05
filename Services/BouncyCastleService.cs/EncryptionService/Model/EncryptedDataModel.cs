namespace EncryptionService.Model
{
    public class EncryptedDataModel
    {
        public byte[]? EncryptedData { get; set; }
        public byte[]? Signature { get; set; }
    }
}
