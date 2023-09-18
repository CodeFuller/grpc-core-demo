using log4net;
using System.Collections.Generic;
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

                case SecurityType.CertificatesFromDisk:
                    return GetSslServerCredentials();

                default:
                    throw new NotSupportedException($"Security type is not supported by the server: {ConnectionSettings.SecurityType}");
            }
        }

        private static ServerCredentials GetSslServerCredentials()
        {
            var certificatesFolderPath = Path.Combine(@"c:\temp\certificates", ConnectionSettings.HostName);

            // https://stackoverflow.com/questions/37714558
            var rootCertificates = File.ReadAllText(Path.Combine(certificatesFolderPath, "ca.crt"));
            var certificateChain = File.ReadAllText(Path.Combine(certificatesFolderPath, "server.crt"));
            var serverKey = File.ReadAllText(Path.Combine(certificatesFolderPath, "server.key"));
            var keyPair = new KeyCertificatePair(certificateChain, serverKey);

            return new SslServerCredentials(new List<KeyCertificatePair> { keyPair }, rootCertificates, SslClientCertificateRequestType.DontRequest);
        }
    }
}
