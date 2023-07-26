using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Common.Certificates
{
    public static class X509Certificate2Extensions
    {
        public static string ExportCertificate(this X509Certificate2 certificate)
        {
            var certificateData = certificate.Export(X509ContentType.Cert);

            return GetPemContent("CERTIFICATE", certificateData);
        }

        public static string ExportPrivateRsaKey(this X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException("Certificate does not contain private key");
            }

            if (!(certificate.PrivateKey is RSACryptoServiceProvider rsaCryptoServiceProvider))
            {
                throw new InvalidOperationException($"Certificate has non-RSA private key ({certificate.PrivateKey?.GetType()})");
            }

            if (rsaCryptoServiceProvider.PublicOnly)
            {
                throw new InvalidOperationException("RSACryptoServiceProvider does not contain a private key");
            }

            var parameters = rsaCryptoServiceProvider.ExportParameters(includePrivateParameters: true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);

                // Sequence
                writer.Write((byte)0x30);
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);

                    // Version
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 });
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);

                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                return GetPemContent("RSA PRIVATE KEY", stream.GetBuffer());
            }
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

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value)
        {
            // Integer type.
            stream.Write((byte)0x02);

            var prefixZeros = value.TakeWhile(v => v == 0).Count();

            if (prefixZeros == value.Length)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1.
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }

                stream.Write(value, prefixZeros, value.Length - prefixZeros);
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }

                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }
    }
}
