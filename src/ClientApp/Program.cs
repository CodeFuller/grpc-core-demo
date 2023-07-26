using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Common;
using Common.Certificates;
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

                /*
                                var rootCertificates = new List<X509Certificate2>(SslCredentialReader.GetRootCertificates())
                                {
                                    new X509Certificate2(@"c:\temp\certificates\ca.crt"),
                                };
                */
                var rootCertificates = new List<X509Certificate2>
                {
                    SslCredentialReader.GetClientCertificate(),
                };

                for (var i = 0; i < rootCertificates.Count; ++i)
                {
                    var rootCertificate = rootCertificates[i];

                    try
                    {
                        var channel = new Channel(ConnectionSettings.HostName, ConnectionSettings.PortNumber, GetClientCredentials(rootCertificate));
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
                    catch (Exception e)
                    {
                    }
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

        private static ChannelCredentials GetClientCredentials(X509Certificate2 rootCertificate)
        {
            return ConnectionSettings.UseSsl ? GetSslClientCredentials(rootCertificate) : ChannelCredentials.Insecure;
        }

        private static SslCredentials GetSslClientCredentials(X509Certificate2 rootCertificate)
        {
            if (ConnectionSettings.UseControlUpCertificates)
            {
                return SslCredentialReader.CreateSslClientCredentials(rootCertificate);
            }

            var rootCertificates = File.ReadAllText(@"c:\temp\certificates\ca.crt");
            var certificateChain = File.ReadAllText(@"c:\temp\certificates\client.crt");
            var clientKey = File.ReadAllText(@"c:\temp\certificates\client.key");

            // CF TEMP
            var root = new X509Certificate2(@"c:\temp\certificates\ca.crt");
            var chain = new X509Certificate2(@"c:\temp\certificates\client.crt");

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
