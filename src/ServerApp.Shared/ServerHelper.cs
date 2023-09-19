using log4net;
using Common;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using System.IO;
using System;

namespace ServerApp.Shared
{
    public static class ServerHelper
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerHelper");

        public static void StartServer()
        {
            Log.Info($"Starting server at {ConnectionSettings.HostName}:{ConnectionSettings.PortNumber} ...");
            Log.Info($"Server security type: {ConnectionSettings.SecurityType}");

            ConnectionSettings.ConfigureLogging();

            var server = new Server
            {
                Services = { Greeter.BindService(new GreeterService()) },
                Ports = { new ServerPort(ConnectionSettings.HostName, ConnectionSettings.PortNumber, GetServerCredentials()) }
            };

            server.Start();
        }

        private static ServerCredentials GetServerCredentials()
        {
            switch (ConnectionSettings.SecurityType)
            {
                case SecurityType.Insecure:
                    return ServerCredentials.Insecure;

                case SecurityType.CertificateFromDisk:
                    return GetServerCredentialsForCertificateFromDisk();

                case SecurityType.GeneratedCertificate:
                    return GetServerCredentialsForGeneratedCertificate();

                default:
                    throw new NotSupportedException($"Security type is not supported by the server: {ConnectionSettings.SecurityType}");
            }
        }

        private static ServerCredentials GetServerCredentialsForCertificateFromDisk()
        {
            var certificatesFolderPath = Path.Combine(@"c:\temp\certificates", ConnectionSettings.HostName);

            Log.Info($"Reading certificates from folder '{certificatesFolderPath}' ...");

            // https://stackoverflow.com/questions/37714558
            var serverCertificate = File.ReadAllText(Path.Combine(certificatesFolderPath, "server.crt"));
            var serverKey = File.ReadAllText(Path.Combine(certificatesFolderPath, "server.key"));

            return CreateServerCredentials(null, serverCertificate, serverKey);
        }

        private static ServerCredentials GetServerCredentialsForGeneratedCertificate()
        {
            var keyPair = ConnectionSettings.GetAsymmetricCipherKeyPair();
            var serverCertificate = CertificateManager.GenerateCertificate(ConnectionSettings.CertificateIssuer, commonName: ConnectionSettings.HostName, keyPair);

            return CreateServerCredentials(null, serverCertificate.ExportCertificate(), ConnectionSettings.PrivateKey);
        }

        private static ServerCredentials CreateServerCredentials(string rootCertificateContent, string serverCertificateContent, string privateKeyContent)
        {
            var keyCertificatePair = new KeyCertificatePair(serverCertificateContent, privateKeyContent);

            return new SslServerCredentials(new[] { keyCertificatePair }, rootCertificateContent, SslClientCertificateRequestType.DontRequest);
        }
    }
}
