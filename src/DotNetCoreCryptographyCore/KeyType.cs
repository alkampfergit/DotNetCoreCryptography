namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// It will contain a byte that specify key
    /// type when it is serialized to byte array
    /// </summary>
    public enum KeyType : byte
    {
        Unknown = 0,

        /// <summary>
        /// Legacy AES-256-CBC key (unauthenticated). Retained only to decrypt
        /// data produced by format v1; new keys use <see cref="Aes256Gcm"/>.
        /// </summary>
        Aes256 = 1,

        /// <summary>
        /// AES-256-GCM key (authenticated encryption). Default since format v2.
        /// </summary>
        Aes256Gcm = 2,
    }
}
