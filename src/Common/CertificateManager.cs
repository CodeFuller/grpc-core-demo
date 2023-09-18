using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Linq;

namespace Common
{
    public static class CertificateManager
    {
        private const string SignatureAlgorithm = "SHA256WithRSA";

        public const int DefaultValidityInYears = 5;

        public static X509Certificate2 GetMonitorCertificateFromStore()
        {
            var certificatesCollection = ReadCertificateFromStore("cuMonitor", X509FindType.FindBySubjectName, StoreName.TrustedPublisher, StoreLocation.CurrentUser);

            if (!certificatesCollection.Any())
            {
                throw new InvalidOperationException("Monitor certificate does not exist in the store");
            }

            return certificatesCollection.Single();
        }

        public static List<X509Certificate2> ReadCertificateFromStore(string searchString, X509FindType findType, StoreName storeName, StoreLocation storeLocation)
        {
            var certStore = new X509Store(storeName, storeLocation);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(findType, searchString, false)
                .Cast<X509Certificate2>()
                .Where(c => c.HasPrivateKey)
                .ToList();
            certStore.Close();

            return certCollection;
        }

        public static X509Certificate2 GenerateCertificate(string issuer, string commonName, AsymmetricCipherKeyPair issuerKeyPair)
        {
            var random = new SecureRandom();
            var certificateGenerator = new X509V3CertificateGenerator();

            certificateGenerator.SetSerialNumber(new BigInteger("1"));
            certificateGenerator.SetIssuerDN(new X509Name(issuer));
            certificateGenerator.SetSubjectDN(new X509Name($"O=ControlUp, CN={commonName}"));
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(DefaultValidityInYears));

            certificateGenerator.SetPublicKey(issuerKeyPair.Public);

            var signatureFactory = new Asn1SignatureFactory(SignatureAlgorithm, issuerKeyPair.Private);
            var bouncyCert = certificateGenerator.Generate(signatureFactory);

            var store = new Pkcs12StoreBuilder().Build();
            store.SetKeyEntry($"{commonName}_key", new AsymmetricKeyEntry(issuerKeyPair.Private), new[] { new X509CertificateEntry(bouncyCert) });
            var password = Guid.NewGuid().ToString();

            using (var ms = new MemoryStream())
            {
                store.Save(ms, password.ToCharArray(), random);
                return new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
            }
        }
    }
}
