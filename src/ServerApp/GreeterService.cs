using System.Threading.Tasks;
using Grpc.Core;
using GrpcCoreDemo.Grpc;
using log4net;

namespace ServerApp
{
    internal class GreeterService : Greeter.GreeterBase
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerApp.DemoService");

        public override Task<HelloResponse> SayHello(HelloRequest request, ServerCallContext context)
        {
            Log.Info($"Got request from {request.Name}");

            return Task.FromResult(new HelloResponse { Message = $"Hello, {request.Name}!" });
        }
    }
}
