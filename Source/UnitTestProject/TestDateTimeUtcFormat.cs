using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Xades;
using Microsoft.Xades.GIS;

namespace UnitTestProject
{
    [TestClass]
    public class TestDateTimeUtcFormat
    {
        [TestMethod]
        public void TestDateTime()
        {
            DateTime dtNowUtc = DateTime.UtcNow;
            TimeSpan delta = TimeZoneInfo.Local.GetUtcOffset(DateTime.Now);
            int timeZoneOffsetMinutes = Convert.ToInt32(delta.TotalMinutes);

            var signingTimeOffset = GisSignatureHelper.GetSigningTimeOffset(dtNowUtc, timeZoneOffsetMinutes);
            var timeStr = signingTimeOffset.ToString(SignedSignatureProperties.SIGNING_TIME_FORMAT);
            Console.WriteLine(timeStr);
            CheckDateTime(timeStr, signingTimeOffset);
        }

        void CheckDateTime(string timeStr, DateTimeOffset dt)
        {
            const string regEx = @"(?<year>[0-9]{4})-(?<month>0[1-9]|1[012])-(?<day>0[1-9]|1[0-9]|2[0-9]|3[01])T(?<hour>[0-1]\d|2[0-3]):(?<minute>[0-5]\d):(?<second>[0-5]\d).(?<ms>[0-9]{3})(?<sign>[\+-])(?<utcHour>\d{2}):?(?<utcMin>\d{2})";

            Regex reg = new Regex(regEx);
            var match = reg.Match(timeStr);
            
            Assert.AreEqual(Convert.ToInt32(match.Groups["hour"].Value), dt.Hour);
        }
    }
}
