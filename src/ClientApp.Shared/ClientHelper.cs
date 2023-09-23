using Grpc.Core;
using GrpcCoreDemo.Grpc;
using System.Threading;
using System;
using Common;
using log4net;
using System.IO;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace ClientApp.Shared
{
    public static class ClientHelper
    {
        private static readonly ILog Log = LogManager.GetLogger("ClientHelper");

        public static void RunClient()
        {
            Log.Info($"Creating service client for {ConnectionSettings.ServerHostName}:{ConnectionSettings.ServerPortNumber} ...");
            Log.Info($"Client security type: {ConnectionSettings.SecurityType}");

            ConnectionSettings.ConfigureLogging();

            var channel = new Channel(ConnectionSettings.ServerHostName, ConnectionSettings.ServerPortNumber, GetClientCredentials());
            var client = new Greeter.GreeterClient(channel);

            Log.Info("Subscribing to greeting notifications ...");
            using (var stream = client.SubscribeToGreetingNotifications(new SubscribeToGreetingNotificationsRequest()))
            using (var cancellationTokenSource = new CancellationTokenSource())
            {
                var task = ProcessGreetingNotifications(stream.ResponseStream, cancellationTokenSource.Token);

                // Small delay before subscription is completed.
                Thread.Sleep(TimeSpan.FromMilliseconds(500));

                Log.Info("Sending request to server ...");
                var response = client.SayHello(new HelloRequest { Name = "CodeFuller" });
                Log.Info($"Result: '{response.Message}'");
            }
        }

        private static ChannelCredentials GetClientCredentials()
        {
            switch (ConnectionSettings.SecurityType)
            {
                case SecurityType.Insecure:
                    return ChannelCredentials.Insecure;

                case SecurityType.CertificateFromDisk:
                    return GetClientCredentialsForCertificateFromDisk();

                case SecurityType.GeneratedCertificate:
                    return GetClientCredentialsForGeneratedCertificate();

                case SecurityType.CertificateFromServicePointManager:
                    return GetClientCredentialsForCertificateFromServicePointManager();

                default:
                    throw new NotSupportedException($"Security type is not supported by the client: {ConnectionSettings.SecurityType}");
            }
        }

        private static SslCredentials GetClientCredentialsForCertificateFromDisk()
        {
            var certificatesFolderPath = Path.Combine(@"c:\temp\certificates", ConnectionSettings.ServerHostName);

            Log.Info($"Reading certificate from folder '{certificatesFolderPath}' ...");

            var rootCertificate = File.ReadAllText(Path.Combine(certificatesFolderPath, "ca.crt"));

            return new SslCredentials(rootCertificate);
        }

        private static SslCredentials GetClientCredentialsForGeneratedCertificate()
        {
            var certificateForClientFileName = ConnectionSettings.CertificateForClientFileName;

            if (!File.Exists(ConnectionSettings.CertificateForClientFileName))
            {
                throw new InvalidOperationException($"Certificate for client is missing - '{certificateForClientFileName}'");
            }

            Log.Info($"Loading client certificate from '{certificateForClientFileName}' ...");
            var certificate = File.ReadAllText(certificateForClientFileName);

            return new SslCredentials(certificate);
        }

        private static SslCredentials GetClientCredentialsForCertificateFromServicePointManager()
        {
            var serverAddress = new Uri($"https://{ConnectionSettings.ServerHostName}:{ConnectionSettings.ServerPortNumber}");

            Log.Info($"Getting server certificate from {serverAddress} ...");

            using (var httpClientHandler = new HttpClientHandler())
            {
                httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                httpClientHandler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErrors) => true;

                var client = new HttpClient(httpClientHandler);
                try
                {
                    using (client.GetAsync(serverAddress).GetAwaiter().GetResult())
                    {
                    }
                }
                catch (HttpRequestException)
                {
                    // The request is expected to fail.
                }
            }

            var servicePoint = ServicePointManager.FindServicePoint(serverAddress);
            var certificate = servicePoint.Certificate;

            if (certificate == null)
            {
                throw new InvalidOperationException("Failed to get server certificate");
            }

            Log.Info("Got server certificate successfully");

            return new SslCredentials((new X509Certificate2(certificate)).ExportCertificate());
        }

        private static async Task ProcessGreetingNotifications(IAsyncStreamReader<GreetingNotification> stream, CancellationToken cancellationToken)
        {
            while (await stream.MoveNext(cancellationToken))
            {
                var notification = stream.Current;
                Log.Info($"Callback called: '{notification.Name}'");
            }
        }
    }
}
