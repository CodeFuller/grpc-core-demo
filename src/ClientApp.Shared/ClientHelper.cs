using Grpc.Core;
using GrpcCoreDemo.Grpc;
using System.Threading;
using System;
using Common;
using log4net;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Security;

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

                case SecurityType.CertificateFromDiskDeliveredViaHttp:
                    return GetClientCredentialsForCertificateDeliveredViaHttp();

                case SecurityType.GeneratedCertificateDeliveredViaFilesystem:
                    return GetClientCredentialsForGeneratedCertificateDeliveredViaFilesystem();

                case SecurityType.GeneratedCertificateDeliveredViaHttp:
                    return GetClientCredentialsForCertificateDeliveredViaHttp();

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

        private static SslCredentials GetClientCredentialsForGeneratedCertificateDeliveredViaFilesystem()
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

        private static SslCredentials GetClientCredentialsForCertificateDeliveredViaHttp()
        {
            var serverAddress = new Uri($"https://{ConnectionSettings.ServerHostName}:{ConnectionSettings.ServerPortNumber}");

            Log.Info($"Getting server certificate from {serverAddress} ...");

            string certificateContent = null;
            var certificateIsValid = false;

            using (var httpClientHandler = new HttpClientHandler())
            {
                httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                httpClientHandler.ServerCertificateCustomValidationCallback = (httpRequestMessage, certificate, certificateChain, policyErrors) =>
                {
                    // We extract certificate content within a callback because original certificate is disposed after callback is called.
                    certificateContent = certificate?.ExportCertificate();

                    void LogCertificateError(string message)
                    {
                        if (ConnectionSettings.ValidateServerCertificate)
                        {
                            Log.Error(message);
                        }
                        else
                        {
                            Log.Debug(message);
                        }
                    }

                    certificateIsValid = policyErrors == SslPolicyErrors.None;
                    if (!certificateIsValid)
                    {
                        LogCertificateError($"Certificate policy errors: {policyErrors}");
                    }

                    if (certificateChain?.ChainStatus?.Any() == true)
                    {
                        var chainStatusInfo = String.Join(Environment.NewLine, certificateChain.ChainStatus.Select((x, i) => $"{i + 1}. {x.Status}: '{x.StatusInformation}'"));
                        LogCertificateError($"Certificate chain status: {chainStatusInfo}");
                    }

                    return true;
                };

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

            if (certificateContent == null)
            {
                throw new InvalidOperationException("Failed to get server certificate");
            }

            if (ConnectionSettings.ValidateServerCertificate && !certificateIsValid)
            {
                throw new InvalidOperationException("Server certificate is not valid");
            }

            Log.Info("Got server certificate successfully");

            return new SslCredentials(certificateContent);
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
