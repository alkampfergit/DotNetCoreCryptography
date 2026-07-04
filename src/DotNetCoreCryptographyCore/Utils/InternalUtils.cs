using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace DotNetCoreCryptographyCore.Utils
{
    internal static class InternalUtils
    {
        /// <summary>
        /// Owner-only file permissions (0600): read + write for the owner, nothing
        /// for group or other.
        /// </summary>
        private const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        /// <summary>
        /// Owner-only directory permissions (0700): the execute/traverse bit is
        /// required in addition to read/write for a usable directory.
        /// </summary>
        private const UnixFileMode OwnerOnlyDirectory =
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

        private const UnixFileMode GroupOrOtherAccess =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        /// <summary>
        /// Ensures the key-material directory exists. On Unix it is created with
        /// owner-only permissions (0700) so co-resident users cannot enumerate or
        /// read the key files; on Windows the default ACL is used.
        /// </summary>
        public static void EnsureDirectory(string directoryPath)
        {
            if (Directory.Exists(directoryPath))
            {
                // An existing directory may have been created before this hardening
                // (or by another tool) with looser permissions; tighten it back to
                // owner-only so co-resident users cannot enumerate the key files.
                if (!OperatingSystem.IsWindows())
                {
                    TightenUnixDirectory(directoryPath);
                }
                return;
            }

            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directoryPath);
            }
            else
            {
                Directory.CreateDirectory(directoryPath, OwnerOnlyDirectory);
            }
        }

        /// <summary>
        /// Writes a brand new file with owner-only permissions (0600 on Unix).
        /// <see cref="FileMode.CreateNew"/> makes the create atomic: it throws
        /// <see cref="IOException"/> if the file already exists, which both closes
        /// the time-of-check/time-of-use race against a concurrent creator and
        /// guarantees the restrictive permissions are set at creation time (no
        /// window where the file exists with default permissions).
        /// </summary>
        public static void WriteNewFileRestricted(string filePath, byte[] contents)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = OwnerOnlyFile;
            }

            using var stream = new FileStream(filePath, options);
            stream.Write(contents, 0, contents.Length);
        }

        /// <summary>
        /// Writes (creating or overwriting) a file with owner-only permissions
        /// (0600 on Unix). Unlike <see cref="WriteNewFileRestricted"/> this does not
        /// guard against concurrent creation; use it for files that are legitimately
        /// rewritten (e.g. metadata) rather than for key material. The restrictive
        /// mode is applied atomically when the file is first created; on overwrite the
        /// existing (already restricted) mode is preserved.
        /// </summary>
        public static void WriteFileRestricted(string filePath, byte[] contents)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.Create,
                Access = FileAccess.Write,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = OwnerOnlyFile;
            }

            using var stream = new FileStream(filePath, options);
            stream.Write(contents, 0, contents.Length);
        }

        /// <summary>
        /// Verifies, on Unix, that an existing key file is not accessible to group
        /// or other. If it is, the permissions are tightened back to owner-only
        /// (0600) and a warning is emitted: the file was created before this
        /// hardening (or by another tool) and the key may already have been exposed.
        /// No-op on Windows, where file access is governed by ACLs.
        /// </summary>
        public static void EnsureOwnerOnlyPermissions(string filePath)
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            TightenUnixPermissions(filePath);
        }

        [UnsupportedOSPlatform("windows")]
        private static void TightenUnixPermissions(string filePath)
        {
            var mode = File.GetUnixFileMode(filePath);
            if ((mode & GroupOrOtherAccess) == UnixFileMode.None)
            {
                return;
            }

            Trace.TraceWarning(
                "Key file '{0}' was group/other-accessible ({1}); restricting to owner-only (0600). " +
                "The key material may already have been exposed to other local users.",
                filePath,
                mode);
            File.SetUnixFileMode(filePath, OwnerOnlyFile);
        }

        [UnsupportedOSPlatform("windows")]
        private static void TightenUnixDirectory(string directoryPath)
        {
            var mode = File.GetUnixFileMode(directoryPath);
            if ((mode & GroupOrOtherAccess) == UnixFileMode.None)
            {
                return;
            }

            Trace.TraceWarning(
                "Key directory '{0}' was group/other-accessible ({1}); restricting to owner-only (0700). " +
                "The key files it holds may already have been enumerated by other local users.",
                directoryPath,
                mode);
            File.SetUnixFileMode(directoryPath, OwnerOnlyDirectory);
        }
    }
}
