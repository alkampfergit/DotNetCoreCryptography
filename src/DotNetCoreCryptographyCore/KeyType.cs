namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// It will contain a byte that specify key
    /// type when it is serialized to byte array
    /// </summary>
    public enum KeyType : byte
    {
        Unknown = 0,
        Aes256 = 1,
    }
}
