using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Common
{
    public static class CertificateManager
    {
        private const string SignatureAlgorithm = "SHA256WithRSA";

        public const int DefaultValidityInYears = 5;

        public static X509Certificate2 GenerateServerCertificate(string issuer, string subject, AsymmetricCipherKeyPair issuerKeyPair)
        {
            return GenerateCertificate(issuer, subject, issuerKeyPair);
        }

        public static X509Certificate2 GenerateClientCertificate(string issuer, string subject, AsymmetricCipherKeyPair issuerKeyPair)
        {
            return GenerateCertificate(issuer, subject, issuerKeyPair);
        }

        private static X509Certificate2 GenerateCertificate(string issuer, string subject, AsymmetricCipherKeyPair issuerKeyPair)
        {
            var random = new SecureRandom();
            var certificateGenerator = new X509V3CertificateGenerator();

            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetIssuerDN(new X509Name(issuer));
            certificateGenerator.SetSubjectDN(new X509Name(subject));
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(DefaultValidityInYears));

            certificateGenerator.SetPublicKey(issuerKeyPair.Public);

            var signatureFactory = new Asn1SignatureFactory(SignatureAlgorithm, issuerKeyPair.Private);
            var bouncyCert = certificateGenerator.Generate(signatureFactory);

            var store = new Pkcs12StoreBuilder().Build();
            store.SetKeyEntry("key", new AsymmetricKeyEntry(issuerKeyPair.Private), new[] { new X509CertificateEntry(bouncyCert) });
            var password = Guid.NewGuid().ToString();

            using (var ms = new MemoryStream())
            {
                store.Save(ms, password.ToCharArray(), random);
                return new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
            }
        }
    }
}
