using System.IO;

namespace DotNetCoreCryptographyCore.Utils
{
    internal static class InternalUtils
    {
        public static void EnsureDirectory(string directoryPath)
        {
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }
        }
    }
}
