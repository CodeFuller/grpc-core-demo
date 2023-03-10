using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Common;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using log4net;
using log4net.Config;

namespace ClientApp
{
    public static class Program
    {
        private static readonly ILog Log = LogManager.GetLogger("ClientApp.Program");

        public static int Main(string[] args)
        {
            try
            {
                XmlConfigurator.Configure(new FileInfo("log4net.config"));

                Log.Info("Creating service client ...");

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

                Log.Info("Exiting ...");

                return 0;
            }
            catch (Exception e)
            {
                Log.Error("ClientApp has failed", e);

                return e.HResult;
            }
        }

        private static ChannelCredentials GetClientCredentials()
        {
            return ConnectionSettings.UseSsl ? GetSslClientCredentials() : ChannelCredentials.Insecure;
        }

        private static SslCredentials GetSslClientCredentials()
        {
            var rootCertificates = File.ReadAllText(@"c:\temp\certificates\ca.crt");
            var certificateChain = File.ReadAllText(@"c:\temp\certificates\client.crt");
            var clientKey = File.ReadAllText(@"c:\temp\certificates\client.key");

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
