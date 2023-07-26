using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;

namespace Common.Certificates
{
    public static class CertificateExporter
    {
        public static string ExportX509CertificateAsPEM(this X509Certificate2 certificate)
        {
            return certificate.ExportCertificate();
            /*
                        var oldCertificate = certificate.ExportX509CertificateAsPEMOld();
                        var newCertificate = certificate.ExportCertificate();

                        if (oldCertificate != newCertificate)
                        {
                            throw new InvalidOperationException("Oops: certificate was exported incorrectly");
                        }

                        return newCertificate;
            */
        }

        public static string ExportX509CertificateAsPEMOld(this X509Certificate2 certificate)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");

            AppendByteArrayAsPEM(builder, certificate.Export(X509ContentType.Cert));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        private static void AppendByteArrayAsPEM(StringBuilder builder, byte[] input)
        {
            var base64 = Convert.ToBase64String(input);

            for (int i = 0; i < base64.Length; i += 64)
            {
                var line = base64.Substring(i, Math.Min(64, base64.Length - i));
                builder.AppendLine(line);
            }
        }

        public static string ExportX509PrivateRSAKey(this X509Certificate2 cert)
        {
            return cert.ExportPrivateRsaKey();

/*
            var oldRsaKey = cert.ExportX509PrivateRSAKeyOld();
            var oldRsaKey2 = cert.ExportX509PrivateRSAKeyOld();
            if (oldRsaKey != oldRsaKey2)
            {
            }

            var newRsaKey = cert.ExportPrivateRsaKey();

            if (oldRsaKey != newRsaKey)
            {
                throw new InvalidOperationException("Oops: RSA key was exported incorrectly");
            }

            return newRsaKey;
*/
        }

        public static string ExportX509PrivateRSAKeyOld(this X509Certificate2 cert)
        {
            var csp = (RSACryptoServiceProvider)cert.PrivateKey;

            if (csp.PublicOnly)
                throw new ArgumentException("CSP does not contain a private key", "csp");

            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
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

                var outputStream = new StringWriter();

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }

                outputStream.WriteLine("-----END RSA PRIVATE KEY-----");

                return outputStream.ToString();
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
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

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }

            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }

                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
    }
}
