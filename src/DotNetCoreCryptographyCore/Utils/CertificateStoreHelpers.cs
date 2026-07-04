#nullable enable
using System.Security.Cryptography.X509Certificates;

namespace DotNetCoreCryptographyCore.Utils
{
    internal static class CertificateStoreHelpers
    {
        public static X509Certificate2? GetCertificateFromThumbprint(string thumbprint)
        {
            return GetCertificateFromStore(thumbprint, StoreLocation.LocalMachine) ??
                GetCertificateFromStore(thumbprint, StoreLocation.CurrentUser);
        }

        private static X509Certificate2? GetCertificateFromStore(string thumbprint, StoreLocation storeLocation)
        {
            using X509Store store = new X509Store(storeLocation);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certificates = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                thumbprint,
                false);

            if (certificates.Count == 1)
            {
                return certificates[0];
            }

            return null;
        }
    }
}
