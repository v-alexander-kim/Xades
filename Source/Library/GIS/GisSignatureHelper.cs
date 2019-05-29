using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using CryptoPro.Sharpei;
using CryptoPro.Sharpei.Xml;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Microsoft.Xades.GIS
{
    public static class GisSignatureHelper
    {
        public const bool _PRESERVE_WHITESPACE = true;

        public static string GetSignedRequestXades(string request, X509Certificate2 certificate, string privateKeyPassword)
        {
            var provider = SigningKeyProvider.GetProvider(certificate);
            provider.SetCointainerPassword(privateKeyPassword);

            var originalDoc = new XmlDocument() { PreserveWhitespace = _PRESERVE_WHITESPACE };
            originalDoc.LoadXml(request);

            var signatureid = String.Format("xmldsig-{0}", Guid.NewGuid().ToString().ToLower());
            var signedXml = GetXadesSignedXml(provider, originalDoc, signatureid);

            var keyInfo = GetKeyInfo(Convert.ToBase64String(certificate.GetRawCertData()));
            signedXml.KeyInfo = keyInfo;

            var xadesInfo = GetXadesInfo(certificate);

            var xadesObject = GetXadesObject(provider, xadesInfo, signatureid);
            signedXml.AddXadesObject(xadesObject, provider.DigestMethod);

            signedXml.ComputeSignature();

            InjectSignatureToOriginalDoc(signedXml, originalDoc);

            return originalDoc.OuterXml;
        }

        public static XadesInfo GetXadesInfo(X509Certificate2 certificate)
        {
            XadesInfo xadesInfo = new XadesInfo();
            xadesInfo.RawPK = Convert.ToBase64String(certificate.GetRawCertData());
            xadesInfo.SigningDateTimeUTC = DateTime.UtcNow;
            TimeSpan delta = TimeZoneInfo.Local.GetUtcOffset(DateTime.Now);
            xadesInfo.TimeZoneOffsetMinutes = Convert.ToInt32(delta.TotalMinutes);
            return xadesInfo;
        }

        public static void InjectSignatureToOriginalDoc(XadesSignedXml signedXml, XmlDocument originalDoc)
        {
            var xmlSig = signedXml.GetXml();
            var signedDataContainer = signedXml.GetIdElement(originalDoc, "signed-data-container");
            signedDataContainer.InsertBefore(originalDoc.ImportNode(xmlSig, true), signedDataContainer.FirstChild);
        }

        public static XadesObject GetXadesObject(SigningKeyProvider provider, XadesInfo xadesInfo, string signatureid)
        {
            XadesObject xadesObject = new XadesObject();
            xadesObject.QualifyingProperties.Target = String.Format("#{0}", signatureid);
            xadesObject.QualifyingProperties.SignedProperties.Id = String.Format("{0}-signedprops", signatureid);
            SignedSignatureProperties signedSignatureProperties = xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties;


            var x509CertificateParser = new Org.BouncyCastle.X509.X509CertificateParser();
            X509Certificate bouncyCert = x509CertificateParser.ReadCertificate(Convert.FromBase64String(xadesInfo.RawPK));

            var cert = new Cert
            {
                IssuerSerial =
                {
                    X509IssuerName = GetOidRepresentation(bouncyCert.IssuerDN.ToString()),
                    X509SerialNumber = bouncyCert.SerialNumber.ToString()
                }
            };

            cert.CertDigest.DigestMethod.Algorithm = provider.DigestMethod;

            var rawCertData = Convert.FromBase64String(xadesInfo.RawPK);
            var pkHash = HashAlgorithm.Create(provider.HashAlgorithmName);
            var hashValue = pkHash.ComputeHash(rawCertData);
            cert.CertDigest.DigestValue = hashValue;

            signedSignatureProperties.SigningCertificate.CertCollection.Add(cert);

            signedSignatureProperties.SigningTime = GetSigningTimeOffset(xadesInfo.SigningDateTimeUTC, xadesInfo.TimeZoneOffsetMinutes);
            return xadesObject;
        }

        public static DateTimeOffset GetSigningTimeOffset(DateTime dtUTC, int timeZoneOffsetMinutes)
        {
            var dtUnspecified = DateTime.SpecifyKind(dtUTC.AddMinutes(timeZoneOffsetMinutes), DateTimeKind.Unspecified);
            return new DateTimeOffset(dtUnspecified, new TimeSpan(0, timeZoneOffsetMinutes, 0));
        }

        public static XadesSignedXml GetXadesSignedXml(SigningKeyProvider provider, XmlDocument originalDoc, string signatureid)
        {
            var signedXml = new XadesSignedXml(originalDoc) { SigningKey = provider.SigningKey };

            signedXml.Signature.Id = signatureid;
            signedXml.SignatureValueId = String.Format("{0}-sigvalue", signatureid);

            var reference = new Reference
            {
                Uri = "#signed-data-container",
                DigestMethod = provider.DigestMethod,
                Id = String.Format("{0}-ref0", signatureid)
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigCanonicalizationUrl;
            signedXml.SignedInfo.SignatureMethod = provider.SignatureMethod;

            return signedXml;
        }

        public static KeyInfo GetKeyInfo(string rawPkString)
        {
            var keyInfo = new KeyInfo();

            XmlDocument doc = new XmlDocument();
            XmlElement keyInfoElement = (XmlElement)doc.AppendChild(doc.CreateElement("ds", "KeyInfo", "http://www.w3.org/2000/09/xmldsig#"));
            var x509DataElement = doc.CreateElement("ds", "X509Data", "http://www.w3.org/2000/09/xmldsig#");
            var x509DataNode = keyInfoElement.AppendChild(x509DataElement);
            x509DataNode.AppendChild(doc.CreateElement("ds", "X509Certificate", "http://www.w3.org/2000/09/xmldsig#")).InnerText =
                rawPkString;

            keyInfo.AddClause(new KeyInfoNode(x509DataElement));
            //keyInfo.AddClause(new KeyInfoX509Data(certificate));
            return keyInfo;
        }

        /// <summary>
        /// Заменяет части IssuerName на OID. https://technet.microsoft.com/en-us/library/cc772812(WS.10).aspx
        /// </summary>
        /// <param name="issuerName"></param>
        /// <returns></returns>
        private static string GetOidRepresentation(string issuerName)
        {
            var result = issuerName;
            result = result.Replace("E=", "1.2.840.113549.1.9.1=");
            result = result.Replace("unstructuredName=", "1.2.840.113549.1.9.2=");
            return result;
        }
    }
}
