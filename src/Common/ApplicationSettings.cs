using System.IO;
using Newtonsoft.Json;

namespace Common
{
    public static class ApplicationSettings
    {
        public static ConnectionSettings GetConnectionSettings()
        {
            var appSettingsJson = File.ReadAllText("AppSettings.json");

            return JsonConvert.DeserializeObject<ConnectionSettings>(appSettingsJson);
        }

        public static void ConfigureLogging()
        {
            // System.Environment.SetEnvironmentVariable("GRPC_VERBOSITY", "debug");
            // System.Environment.SetEnvironmentVariable("GRPC_TRACE", "handshaker");
        }
    }
}
