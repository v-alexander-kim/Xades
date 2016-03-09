using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.Xades.GIS
{
    public static class CertificateExtension
    {
        public static void SetContainerPassword(this X509Certificate2 certificate, string pass)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            var key = (ICspAsymmetricAlgorithm)certificate.PrivateKey;

            IntPtr ProviderHandle = IntPtr.Zero;
            byte[] PinBuffer = Encoding.ASCII.GetBytes(pass);

            if (!InteropMethods.CryptAcquireContext(
                ref ProviderHandle,
                key.CspKeyContainerInfo.KeyContainerName,
                key.CspKeyContainerInfo.ProviderName,
                key.CspKeyContainerInfo.ProviderType,
                InteropMethods.CryptContextFlags.Silent))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!InteropMethods.CryptSetProvParam(
                ProviderHandle,
                InteropMethods.CryptParameter.KeyExchangePin,
                PinBuffer,
                0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (InteropMethods.CertSetCertificateContextProperty(
                certificate.Handle,
                InteropMethods.CertificateProperty.CryptoProviderHandle,
                0,
                ProviderHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }

    internal static class InteropMethods
    {
        internal enum CryptContextFlags
        {
            None = 0,
            Silent = 0x40
        }

        internal enum CertificateProperty
        {
            None = 0,
            CryptoProviderHandle = 0x1
        }

        internal enum CryptParameter
        {
            None = 0,
            KeyExchangePin = 0x20
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireContext(
            ref IntPtr hProv,
            string containerName,
            string providerName,
            int providerType,
            CryptContextFlags flags
            );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CryptSetProvParam(
            IntPtr hProv,
            CryptParameter dwParam,
            [In] byte[] pbData,
            uint dwFlags);

        [DllImport("CRYPT32.DLL", SetLastError = true)]
        internal static extern bool CertSetCertificateContextProperty(
            IntPtr pCertContext,
            CertificateProperty propertyId,
            uint dwFlags,
            IntPtr pvData
            );
    }
}
