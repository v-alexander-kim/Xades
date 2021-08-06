﻿using System;
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
            var certificateStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certificateStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var certificateCollection = certificateStore.Certificates.Find((X509FindType)Enum.Parse(typeof(X509FindType), "FindByThumbprint"), certificateThumbprint, false);
            return certificateCollection.Count != 0 ? certificateCollection[0] : null;
        }
    }
}
