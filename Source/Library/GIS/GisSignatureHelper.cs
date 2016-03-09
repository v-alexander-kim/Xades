using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Microsoft.Xades.GIS
{
    public static class GisSignatureHelper
    {
        public const bool _PRESERVE_WHITESPACE = true;
        public const string XmlDsigGost3411UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
        public const string XmlDsigGost3410UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
        public const string XmlDsigCanonicalizationUrl = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"; 

        public static string GetSignedRequestXades(string request, X509Certificate2 certificate, string privateKeyPassword)
        {
            var originalDoc = new XmlDocument() { PreserveWhitespace = _PRESERVE_WHITESPACE };
            originalDoc.LoadXml(request);

            var signatureid = String.Format("xmldsig-{0}", Guid.NewGuid().ToString().ToLower());
            var signedXml = GetXadesSignedXml(certificate, originalDoc, signatureid, privateKeyPassword);

            var keyInfo = GetKeyInfo(Convert.ToBase64String(certificate.GetRawCertData()));
            signedXml.KeyInfo = keyInfo;

            var xadesInfo = GetXadesInfo(certificate);

            var xadesObject = GetXadesObject(xadesInfo, signatureid);
            signedXml.AddXadesObject(xadesObject);

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

        public static XadesObject GetXadesObject(XadesInfo xadesInfo, string signatureid)
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

            cert.CertDigest.DigestMethod.Algorithm = XmlDsigGost3411UrlObsolete;

            var rawCertData = Convert.FromBase64String(xadesInfo.RawPK);

            // TODO Заменить на вызов PInvoke или OpenSSL
            var pkHash = HashAlgorithm.Create("GOST3411");
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



        public static XadesSignedXml GetXadesSignedXml(X509Certificate2 certificate, XmlDocument originalDoc, string signatureid, string privateKeyPassword)
        {
            var secureString = new SecureString();
            foreach (var ch in privateKeyPassword)
                secureString.AppendChar(ch);

           // var provider = (Gost3410CryptoServiceProvider)certificate.PrivateKey;
            var provider = certificate.PrivateKey;
            //certificate.SetContainerPassword(privateKeyPassword);
            //provider.SetContainerPassword(secureString);

            var signedXml = new XadesSignedXml(originalDoc) { SigningKey = provider };

            signedXml.Signature.Id = signatureid;
            signedXml.SignatureValueId = String.Format("{0}-sigvalue", signatureid);

            var reference = new Reference
            {
                Uri = "#signed-data-container",
                DigestMethod = XmlDsigGost3411UrlObsolete,
                Id = String.Format("{0}-ref0", signatureid)
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            signedXml.SignedInfo.CanonicalizationMethod = XmlDsigCanonicalizationUrl;
            signedXml.SignedInfo.SignatureMethod = XmlDsigGost3410UrlObsolete;

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
            return result;
        }
    }
}
