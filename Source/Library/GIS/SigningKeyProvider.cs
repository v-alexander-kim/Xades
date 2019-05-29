using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CryptoPro.Sharpei;
using CryptoPro.Sharpei.Xml;

namespace Microsoft.Xades.GIS
{
    public abstract class SigningKeyProvider
    {
        protected X509Certificate2 _certificate;
        public abstract string DigestMethod { get; }
        public abstract string SignatureMethod { get; }
        public abstract string HashAlgorithmName { get; }
        public virtual AsymmetricAlgorithm SigningKey { get { return _certificate.PrivateKey; } }

        protected SigningKeyProvider(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        protected SecureString FormSecureString(string containerPassword)
        {
            if (string.IsNullOrEmpty(containerPassword))
                throw new ArgumentException("Missing container password");

            var secureString = new SecureString();
            foreach (var ch in containerPassword)
                secureString.AppendChar(ch);

            return secureString;
        }

        public abstract void SetCointainerPassword(string containerPassword);

        public static SigningKeyProvider GetProvider(X509Certificate2 certificate)
        {
            if (certificate == null || certificate.PrivateKey == null)
                throw new ArgumentException("Missing Certificate.PrivateKey");

            switch (certificate.PrivateKey.SignatureAlgorithm)
            {
                case CPSignedXml.XmlDsigGost3410Url: return new SigningKeyProviderGost2001(certificate);
                case CPSignedXml.XmlDsigGost3410_2012_256Url: return new SigningKeyProviderGost2012Bit256(certificate);
                case CPSignedXml.XmlDsigGost3410_2012_512Url: return new SigningKeyProviderGost2012Bit512(certificate);
                default: throw new NotSupportedException("Certificate.PrivateKey.SignatureAlgorithm not supported");
            }
        }
    }

    internal class SigningKeyProviderGost2001 : SigningKeyProvider
    {
        private const string HashAlgorithmConstName = "GOST3411";

        public SigningKeyProviderGost2001(X509Certificate2 certificate) : base(certificate) { }

        public override string DigestMethod { get { return CPSignedXml.XmlDsigGost3411Url; } }
        public override string SignatureMethod { get { return CPSignedXml.XmlDsigGost3410Url; } }
        public override string HashAlgorithmName { get { return HashAlgorithmConstName; } }

        public override void SetCointainerPassword(string containerPassword)
        {
            var provider = (Gost3410CryptoServiceProvider)_certificate.PrivateKey;
            if (provider == null)
                throw new InvalidCastException("Cannot conver a Certificate.PrivateKey to Gost3410CryptoServiceProvider.");

            var secureString = FormSecureString(containerPassword);
            provider.SetContainerPassword(secureString);
        }
    }

    internal class SigningKeyProviderGost2012Bit256 : SigningKeyProvider
    {
        private const string HashAlgorithmConstName = "GOST3411_2012_256";

        public SigningKeyProviderGost2012Bit256(X509Certificate2 certificate) : base(certificate) { }

        public override string DigestMethod { get { return CPSignedXml.XmlDsigGost3411_2012_256Url; } }
        public override string SignatureMethod { get { return CPSignedXml.XmlDsigGost3410_2012_256Url; } }
        public override string HashAlgorithmName { get { return HashAlgorithmConstName; } }

        public override void SetCointainerPassword(string containerPassword)
        {
            var provider = (Gost3410_2012_256CryptoServiceProvider)_certificate.PrivateKey;
            if (provider == null)
                throw new InvalidCastException("Cannot conver a Certificate.PrivateKey to Gost3410_2012_256CryptoServiceProvider.");

            var secureString = FormSecureString(containerPassword);
            provider.SetContainerPassword(secureString);
        }
    }

    internal class SigningKeyProviderGost2012Bit512 : SigningKeyProvider
    {
        private const string HashAlgorithmConstName = "GOST3411_2012_512";

        public SigningKeyProviderGost2012Bit512(X509Certificate2 certificate) : base(certificate) { }

        public override string DigestMethod { get { return CPSignedXml.XmlDsigGost3411_2012_512Url; } }
        public override string SignatureMethod { get { return CPSignedXml.XmlDsigGost3410_2012_512Url; } }
        public override string HashAlgorithmName { get { return HashAlgorithmConstName; } }

        public override void SetCointainerPassword(string containerPassword)
        {
            var provider = (Gost3410_2012_512CryptoServiceProvider)_certificate.PrivateKey;
            if (provider == null)
                throw new InvalidCastException("Cannot conver a Certificate.PrivateKey to Gost3410_2012_512CryptoServiceProvider.");

            var secureString = FormSecureString(containerPassword);
            provider.SetContainerPassword(secureString);
        }
    }
}