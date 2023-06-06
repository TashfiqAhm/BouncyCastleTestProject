namespace EncryptionService.Model
{
    public class SignedDataContainer
    {
        public byte[] SerializedContainer { get; set; }
        public byte[] Signature { get; set; }
    }
}
