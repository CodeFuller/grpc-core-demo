using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Grpc.Core;

namespace Common.Certificates
{
    public static class SslCredentialReader
    {
        public static SslServerCredentials CreateSslServerCredentialsFromStore()
        {
            var certificate = GetServerCertificate();
            var keyPair = new KeyCertificatePair(certificate.ExportX509CertificateAsPEM(), certificate.ExportX509PrivateRSAKey());
            return new SslServerCredentials(new[] { keyPair });
        }

        public static X509Certificate2 GetMonitorCertificate()
        {
            return GetServerCertificate();
        }

        public static SslCredentials CreateSslClientCredentialsFromStore(VerifyPeerCallback verifyPeerCallback)
        {
            var certificate = GetServerCertificate();
            return new SslCredentials(certificate.ExportX509CertificateAsPEM(), null, verifyPeerCallback);
        }

        // CF TEMP: Call GetMonitorCertificate instead.
        private static X509Certificate2 GetServerCertificate()
        {
            var certStore = new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(X509FindType.FindBySubjectName, "cuMonitor", false)
                .Cast<X509Certificate2>()
                .Where(c => c.HasPrivateKey)
                .ToList();

            certStore.Close();

            return certCollection.Single();
        }

        public static SslCredentials CreateSslClientCredentials(X509Certificate2 rootCertificate)
        {
            // CF MEGATEMP
            return CreateSslClientCredentialsFromStorage(rootCertificate);
            // return CreateSslClientCredentialsFromDisk(rootCertificate);
        }

        private static SslCredentials CreateSslClientCredentialsFromStorage(X509Certificate2 rootCertificate)
        {
            var certificate = GetClientCertificate();
            var keyPair = new KeyCertificatePair(certificate.ExportX509CertificateAsPEM(), certificate.ExportX509PrivateRSAKey());

            return new SslCredentials(rootCertificate.ExportX509CertificateAsPEM(), keyPair);
        }

        private static SslCredentials CreateSslClientCredentialsFromDisk(X509Certificate2 rootCertificate)
        {
            // CF TEMP
            var clientCertificate = new X509Certificate2(@"c:\temp\certificates\client.crt");

            var exportedRoot = rootCertificate.ExportX509CertificateAsPEM();

            var keyPair = new KeyCertificatePair(clientCertificate.ExportX509CertificateAsPEM(), File.ReadAllText(@"c:\temp\certificates\client.key"));

            return new SslCredentials(rootCertificate.ExportX509CertificateAsPEM(), keyPair);
        }

        // CF TEMP: Call GetAgentCertificate instead.
        public static X509Certificate2 GetClientCertificate()
        {
            var certStore = new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(X509FindType.FindBySubjectName, "cuAgent", false)
                .Cast<X509Certificate2>()
                .Where(c => c.HasPrivateKey)
                .ToList();

            certStore.Close();

            return certCollection.Single();
        }

        private static X509Certificate2 GetClientCertificateFromDisk()
        {
            return new X509Certificate2(@"c:\temp\certificates\client.crt");
        }

        private static X509Certificate2 GetRootClientCertificate()
        {
            var certStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(X509FindType.FindBySubjectName, "cuAgent", false)
                .Cast<X509Certificate2>()
                .Where(c => c.HasPrivateKey)
                .ToList();

            certStore.Close();

            return certCollection.Single();
        }

        // CF TEMP
        public static IReadOnlyCollection<X509Certificate2> GetRootCertificates()
        {
            StringBuilder builder = new StringBuilder();
            X509Store store = new X509Store(StoreName.Root);
            store.Open(OpenFlags.ReadOnly);

            var certificates = new List<X509Certificate2>();

            foreach (X509Certificate2 mCert in store.Certificates)
            {
                certificates.Add(mCert);

                /*
                builder.AppendLine(
                    "# Issuer: " + mCert.Issuer.ToString() + "\n" +
                    "# Subject: " + mCert.Subject.ToString() + "\n" +
                    "# Label: " + mCert.FriendlyName.ToString() + "\n" +
                    "# Serial: " + mCert.SerialNumber.ToString() + "\n" +
                    "# SHA1 Fingerprint: " + mCert.GetCertHashString().ToString() + "\n"
                    // + ExportToPEM(mCert) + "\n"
                    );
                */
            }
            return certificates;
        }
    }
}
