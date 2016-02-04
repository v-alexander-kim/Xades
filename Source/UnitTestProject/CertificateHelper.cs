using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UnitTestProject
{
    public class CertificateHelper
    {
        public static X509Certificate2 GetCertificateByThumbprint(string certificateThumbprint)
        {
            var certificateStore = new X509Store((StoreName)Enum.Parse(typeof(StoreName), "My"),
                (StoreLocation)Enum.Parse(typeof(StoreLocation), "CurrentUser"));
            certificateStore.Open(OpenFlags.ReadOnly);
            var certificateCollection = certificateStore.Certificates.Find((X509FindType)Enum.Parse(typeof(X509FindType), "FindByThumbprint"), certificateThumbprint, false);
            return certificateCollection.Count != 0 ? certificateCollection[0] : null;
        }
    }
}
