using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Xades;
using Microsoft.Xades.GIS;
using Newtonsoft.Json;

namespace UnitTestProject
{
    [TestClass]
    public class TestIntegrationClientServer
    {
        // Здесь необходимо будет подставить отпечаток своего сертификата, которым будете подписывать сообщения на сервере
        //public const string CERTIFICATE_THUMBPRINT = "0A82411F51C4652B4EDAE075683CAFB9966F14FF";

        // Здесь должен быть тестовый сертификат без гостовских алгоритмов
        public const string CERTIFICATE_THUMBPRINT = "53B32A05617568D5A10196404A8401BB5DAD5B7B";
        
        // Здесь необходимо будет подставить пароль сертификата, которым будете подписывать сообщения на сервере
        public const string PRIVATE_KEY_PASSWORD = "";

        [TestMethod]
        [DeploymentItem("docToBeSignedXades.txt")]
        [DeploymentItem("xadesInfo.txt")]
        public void Test()
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(CERTIFICATE_THUMBPRINT));
            Assert.IsFalse(string.IsNullOrWhiteSpace(PRIVATE_KEY_PASSWORD));

            string xmlStr = File.ReadAllText("docToBeSignedXades.txt");

            Client client = new Client();
            Server server = new Server(xmlStr, client);

            server.Run();
        }
    }


    class Server
    {
        private readonly string _xmlStr;
        private readonly Client _client;
        
        public Server(string xmlStr, Client client)
        {
            _xmlStr = xmlStr;
            _client = client;
        }

        public void Run()
        {
            /*
             * 1. Получаем сертификат от клиента
             * 2. Формируем объект xades из сертификата от клиента
             * 3. Подписываем исходное сообщение
             * 4. Вычисляем хеш от SignedInfo и отправляем его для подписи клиенту
             * 5. Изменяем подписанное сообщение - подменяем подпись
             */

            var originalDoc = new XmlDocument() { PreserveWhitespace = true };
            originalDoc.LoadXml(_xmlStr);

            // 1. Получаем сертификат от клиента
            XadesInfo xadesInfo = GetClientXadesInfo();

            // 2. Формируем объект xades из сертификата от клиента
            XadesSignedXml xadesSignedXml = GetXadesSignedXml(xadesInfo, originalDoc);

            // 3. Подписываем исходное сообщение серверным сертификатом
            xadesSignedXml.ComputeSignature();

            // 4. Вычисляем хеш от SignedInfo и отправляем его для подписи клиенту
            HashAlgorithm hash;
            xadesSignedXml.GetSignedInfoHash(out hash);

            var signature = _client.GetSignedHash(Convert.ToBase64String(hash.Hash));

            // 5. Изменяем подписанное сообщение - подменяем подпись
            xadesSignedXml.Signature.SignatureValue = Convert.FromBase64String(signature);

            GisSignatureHelper.InjectSignatureToOriginalDoc(xadesSignedXml, originalDoc);

            Console.WriteLine("Получившееся сообщение:");
            Console.WriteLine(originalDoc.OuterXml);
        }

        private XadesSignedXml GetXadesSignedXml(XadesInfo xadesInfo, XmlDocument originalDoc)
        {
            var certificate = CertificateHelper.GetCertificateByThumbprint(TestIntegrationClientServer.CERTIFICATE_THUMBPRINT);
            Assert.IsNotNull(certificate);

            var signatureid = String.Format("xmldsig-{0}", Guid.NewGuid().ToString().ToLower());

            var xadesSignedXml = GisSignatureHelper.GetXadesSignedXml(certificate, originalDoc, signatureid, TestIntegrationClientServer.PRIVATE_KEY_PASSWORD);

            var keyInfo = GisSignatureHelper.GetKeyInfo(xadesInfo.RawPK);
            xadesSignedXml.KeyInfo = keyInfo;

            var xadesObject = GisSignatureHelper.GetXadesObject(xadesInfo, signatureid);
            var signTimeStr = xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties.SigningTime.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz");
            Console.WriteLine(signTimeStr);
            Assert.IsTrue(signTimeStr.Contains("+09"));

            xadesSignedXml.AddXadesObject(xadesObject);

            return xadesSignedXml;
        }

        private XadesInfo GetClientXadesInfo()
        {
            string json = _client.GetXadesInfo();
            var clientXadesInfo = JsonConvert.DeserializeObject<XadesInfo>(json);
            return clientXadesInfo;
        }
    }


    class Client
    {
        public const string XmlDsigGost3410UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";

        public string GetXadesInfo()
        {
            return File.ReadAllText("xadesInfo.txt");
        }

        public string GetSignedHash(string hashStr)
        {
            var hash = Convert.FromBase64String(hashStr);

            Console.WriteLine(GetHexRepresentation(hash));

            var base64String = SignHashOnServer(hash);
            return base64String;
        }

        private string SignHashOnClient(byte[] hash)
        {
            // Здесь необходимо реализовать подпись хеша на клиенте. Можно, например, использовать ЭЦП Browser plug-in.

            throw new NotImplementedException();
        }

        private string SignHashOnServer(byte[] hash)
        {
            var certificate = CertificateHelper.GetCertificateByThumbprint(TestIntegrationClientServer.CERTIFICATE_THUMBPRINT);
            Assert.IsNotNull(certificate);

            var gost = certificate.PrivateKey;

//            var secureString = new SecureString();
//            foreach (var ch in TestIntegrationClientServer.PRIVATE_KEY_PASSWORD)
//                secureString.AppendChar(ch);

#pragma warning disable 612
            SignatureDescription signDescr =
                (SignatureDescription) CryptoConfig.CreateFromName(XmlDsigGost3410UrlObsolete);
#pragma warning restore 612
            var base64String = Convert.ToBase64String(signDescr.CreateFormatter(gost).CreateSignature(hash));
            return base64String;
        }

        private string GetHexRepresentation(byte[] hashValue)
        {
            StringBuilder res = new StringBuilder();
            foreach (var t in hashValue)
                res.Append(string.Format("{0:X2}", t));
            return res.ToString();
        }
    }
}
