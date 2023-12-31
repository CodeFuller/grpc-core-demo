﻿using log4net;
using Common;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using System.IO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace ServerApp.Shared
{
    public static class ServerHelper
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerHelper");

        public static void StartServer()
        {
            var connectionSettings = ApplicationSettings.GetConnectionSettings();

            Log.Info($"Starting server at {connectionSettings.ServerHostName}:{connectionSettings.ServerPortNumber} ...");
            Log.Info($"Server security type: {connectionSettings.SecurityType}");

            ApplicationSettings.ConfigureLogging();

            var server = new Server
            {
                Services = { Greeter.BindService(new GreeterService()) },
                Ports = { new ServerPort(connectionSettings.ServerHostName, connectionSettings.ServerPortNumber, GetServerCredentials(connectionSettings)) }
            };

            server.Start();
        }

        private static ServerCredentials GetServerCredentials(ConnectionSettings connectionSettings)
        {
            switch (connectionSettings.SecurityType)
            {
                case SecurityType.Insecure:
                    return ServerCredentials.Insecure;

                case SecurityType.CertificateFromDisk:
                    return GetServerCredentialsForCertificateFromDisk(connectionSettings);

                case SecurityType.CertificateFromPfxOnDiskDeliveredViaHttp:
                    return GetServerCredentialsForCertificateFromPfxOnDisk(connectionSettings);

                case SecurityType.CertificateFromStoreDeliveredViaHttp:
                    return GetServerCredentialsForCertificateFromStore(connectionSettings);

                case SecurityType.GeneratedCertificateDeliveredViaHttp:
                    return GetServerCredentialsForGeneratedCertificateDeliveredViaHttp(connectionSettings);

                case SecurityType.GeneratedCertificateDeliveredViaFilesystem:
                    return GetServerCredentialsForGeneratedCertificateDeliveredViaFilesystem(connectionSettings);

                default:
                    throw new NotSupportedException($"Security type is not supported by the server: {connectionSettings.SecurityType}");
            }
        }

        private static ServerCredentials GetServerCredentialsForCertificateFromDisk(ConnectionSettings connectionSettings)
        {
            var certificateFolderPath = Path.Combine(@"c:\temp\certificates", connectionSettings.ServerHostName);

            Log.Info($"Reading certificate from folder '{certificateFolderPath}' ...");

            // https://stackoverflow.com/questions/37714558
            var serverCertificate = File.ReadAllText(Path.Combine(certificateFolderPath, "server.crt"));
            var serverKey = File.ReadAllText(Path.Combine(certificateFolderPath, "server.key"));

            return CreateServerCredentials(serverCertificate, serverKey);
        }

        private static ServerCredentials GetServerCredentialsForCertificateFromPfxOnDisk(ConnectionSettings connectionSettings)
        {
            var certificateFolderPath = Path.Combine(@"c:\temp\certificates", connectionSettings.ServerHostName);

            Log.Info($"Reading certificate from folder '{certificateFolderPath}' ...");

            var serverCertificate = new X509Certificate2(Path.Combine(certificateFolderPath, "server.pfx"), connectionSettings.PfxFilePassword, X509KeyStorageFlags.Exportable);
            return CreateServerCredentials(serverCertificate.ExportCertificate(), serverCertificate.ExportPrivateRsaKey());
        }

        private static ServerCredentials GetServerCredentialsForCertificateFromStore(ConnectionSettings connectionSettings)
        {
            List<X509Certificate2> certificates;

            var certificateSubject = connectionSettings.SubjectOfCertificateInStore;

            using (var certStore = new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine))
            {
                certStore.Open(OpenFlags.ReadOnly);
                certificates = certStore.Certificates.Find(X509FindType.FindBySubjectName, certificateSubject, validOnly: false)
                    .Cast<X509Certificate2>()
                    .Where(c => c.HasPrivateKey)
                    .ToList();

                certStore.Close();
            }

            if (!certificates.Any())
            {
                throw new InvalidOperationException($"There is no certificate matching subject '{certificateSubject}'");
            }

            if (certificates.Count > 1)
            {
                throw new InvalidOperationException($"There are multiple ({certificates.Count}) certificates matching subject '{certificateSubject}'");
            }

            var serverCertificate = certificates.Single();

            return CreateServerCredentials(serverCertificate.ExportCertificate(), serverCertificate.ExportPrivateRsaKey());
        }

        private static ServerCredentials GetServerCredentialsForGeneratedCertificateDeliveredViaHttp(ConnectionSettings connectionSettings)
        {
            var keyPair = GenerateKeyPair();
            var serverCertificate = CertificateManager.GenerateServerCertificate(connectionSettings.CertificateIssuer, connectionSettings.ServerCertificateSubject, keyPair);

            return CreateServerCredentials(serverCertificate.ExportCertificate(), ExportPrivateKey(keyPair));
        }

        private static ServerCredentials GetServerCredentialsForGeneratedCertificateDeliveredViaFilesystem(ConnectionSettings connectionSettings)
        {
            var keyPair = GenerateKeyPair();
            var serverCertificate = CertificateManager.GenerateServerCertificate(connectionSettings.CertificateIssuer, connectionSettings.ServerCertificateSubject, keyPair);

            var certificateForClient = CertificateManager.GenerateClientCertificate(connectionSettings.CertificateIssuer, connectionSettings.ClientCertificateSubject, keyPair).ExportCertificate();
            File.WriteAllText(connectionSettings.CertificateForClientFileName, certificateForClient);

            return CreateServerCredentials(serverCertificate.ExportCertificate(), ExportPrivateKey(keyPair));
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var random = new SecureRandom();

            var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            return keyPairGenerator.GenerateKeyPair();
        }

        private static string ExportPrivateKey(AsymmetricCipherKeyPair keyPair)
        {
            using (TextWriter textWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(keyPair.Private);

                return textWriter.ToString();
            }
        }

        private static ServerCredentials CreateServerCredentials(string serverCertificateContent, string privateKeyContent)
        {
            var keyCertificatePair = new KeyCertificatePair(serverCertificateContent, privateKeyContent);

            return new SslServerCredentials(new[] { keyCertificatePair }, null, SslClientCertificateRequestType.DontRequest);
        }
    }
}
