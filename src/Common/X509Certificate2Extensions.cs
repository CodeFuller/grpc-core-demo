using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Common
{
    public static class X509Certificate2Extensions
    {
        public static string ExportCertificate(this X509Certificate2 certificate)
        {
            var certificateData = certificate.Export(X509ContentType.Cert);

            return GetPemContent("CERTIFICATE", certificateData);
        }

        private static string GetPemContent(string entityName, byte[] data)
        {
            var builder = new StringBuilder();

            builder.AppendLine($"-----BEGIN {entityName}-----");

            var base64Data = Convert.ToBase64String(data);

            const int oneLineLength = 64;
            for (var i = 0; i < base64Data.Length; i += oneLineLength)
            {
                var line = base64Data.Substring(i, Math.Min(oneLineLength, base64Data.Length - i));
                builder.AppendLine(line);
            }

            builder.AppendLine($"-----END {entityName}-----");

            return builder.ToString();
        }
    }
}
