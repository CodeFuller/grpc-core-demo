using System;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using log4net;

namespace ServerApp
{
    internal class GreeterService : Greeter.GreeterBase
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerApp.DemoService");

        private IServerStreamWriter<GreetingNotification> GreetingNotificationsStreamWriter { get; set; }

        public override async Task<HelloResponse> SayHello(HelloRequest request, ServerCallContext context)
        {
            Log.Info($"Got request from {request.Name}");

            if (GreetingNotificationsStreamWriter == null)
            {
                Log.Error("Service is not subscribed to greeting notifications");
                throw new InvalidOperationException();
            }

            await GreetingNotificationsStreamWriter.WriteAsync(new GreetingNotification
            {
                Name = request.Name,
            });

            return new HelloResponse
            {
                Message = $"Hello, {request.Name}!",
                EmptyString = String.Empty,

                // There is no ability to set null for string field because explicit check for null is added in generated code.
                // NullString = null,

                EmptyCollection = { },

                // There is no ability to set null for repeated field because it does not have setter.
                // The field is never null because it is initialized with empty collection.
                // NullCollection = null,
            };
        }

        public override async Task SubscribeToGreetingNotifications(SubscribeToGreetingNotificationsRequest request, IServerStreamWriter<GreetingNotification> responseStream, ServerCallContext context)
        {
            Log.Info("Subscribed to greeting notifications");
            GreetingNotificationsStreamWriter = responseStream;

            await AwaitCancellation(context.CancellationToken);

            Log.Info("Unsubscribed from greeting notifications");
            GreetingNotificationsStreamWriter = null;
        }

        private static Task AwaitCancellation(CancellationToken token)
        {
            var completion = new TaskCompletionSource<object>();
            token.Register(() => completion.SetResult(null));
            return completion.Task;
        }
    }
}
