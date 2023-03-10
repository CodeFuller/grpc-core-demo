using System;
using System.Collections.Generic;
using System.IO;
using Common;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using log4net;
using log4net.Config;

namespace ServerApp
{
    public static class Program
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerApp.Program");

        public static int Main(string[] args)
        {
            try
            {
                XmlConfigurator.Configure(new FileInfo("log4net.config"));

                Log.Info("Starting server ...");

                var server = new Server
                {
                    Services = { Greeter.BindService(new GreeterService()) },
                    Ports = { new ServerPort(ConnectionSettings.HostName, ConnectionSettings.PortNumber, GetServerCredentials()) }
                };

                server.Start();

                Log.Info("Press enter for exit");
                Console.Read();

                Log.Info("Exiting ...");

                return 0;
            }
            catch (Exception e)
            {
                Log.Error("ServerApp has failed", e);

                return e.HResult;
            }
        }

        private static ServerCredentials GetServerCredentials()
        {
            return ConnectionSettings.UseSsl ? GetSslServerCredentials() : ServerCredentials.Insecure;
        }

        private static ServerCredentials GetSslServerCredentials()
        {
            // https://stackoverflow.com/questions/37714558
            var rootCertificates = File.ReadAllText(@"C:\work\_days\2022.12.28\certificates4\ca.crt");
            var certificateChain = File.ReadAllText(@"C:\work\_days\2022.12.28\certificates4\server.crt");
            var serverKey = File.ReadAllText(@"C:\work\_days\2022.12.28\certificates4\server.key");
            var keyPair = new KeyCertificatePair(certificateChain, serverKey);

            return new SslServerCredentials(new List<KeyCertificatePair> { keyPair }, rootCertificates, SslClientCertificateRequestType.RequestAndRequireAndVerify);
        }
    }
}
