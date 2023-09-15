using Grpc.Core;
using GrpcCoreDemo.Grpc;
using System.Threading;
using System;
using Common;
using log4net;
using System.IO;
using System.Threading.Tasks;

namespace ClientApp.Shared
{
    public static class ClientHelper
    {
        private static readonly ILog Log = LogManager.GetLogger("ClientHelper");

        public static void RunClient()
        {
            Log.Info($"Creating service client for {ConnectionSettings.HostName}:{ConnectionSettings.PortNumber} ...");

            var channel = new Channel(ConnectionSettings.HostName, ConnectionSettings.PortNumber, GetClientCredentials());
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
            return ConnectionSettings.UseSsl ? GetSslClientCredentials() : ChannelCredentials.Insecure;
        }

        private static SslCredentials GetSslClientCredentials()
        {
            var certificatesFolderPath = Path.Combine(@"c:\temp\certificates", ConnectionSettings.HostName);

            var rootCertificates = File.ReadAllText(Path.Combine(certificatesFolderPath, "ca.crt"));
            var certificateChain = File.ReadAllText(Path.Combine(certificatesFolderPath, "client.crt"));
            var clientKey = File.ReadAllText(Path.Combine(certificatesFolderPath, "client.key"));

            return new SslCredentials(rootCertificates, new KeyCertificatePair(certificateChain, clientKey));
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
